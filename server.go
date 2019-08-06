package camo

import (
	"context"
	"io"
	"log"
	"strings"
	"sync"

	"golang.org/x/net/ipv4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const metaClientID = "camo-client-id"

const (
	defaultIfaceSendChanSize   = 256
	defaultSessionSendChanSize = 256
	defaultIfaceReadBufSize    = 2048
)

// ServerStream ...
type ServerStream = Gateway_OpenServer

// Server implements grpc Gateway interface
type Server struct {
	ifaceSend chan []byte

	ippool     *IPPool
	cidSession map[string]*Session
	ipSession  map[string]*Session
	mu         sync.RWMutex

	stop     chan struct{}
	stopOnce sync.Once
}

// NewServer ...
func NewServer(ippool *IPPool) *Server {
	s := Server{
		ifaceSend:  make(chan []byte, defaultIfaceSendChanSize),
		ippool:     ippool,
		ipSession:  make(map[string]*Session),
		cidSession: make(map[string]*Session),
		stop:       make(chan struct{}),
	}
	return &s
}

// Serve ...
func (s *Server) Serve(iface *Iface) (err error) {
	defer iface.Close()

	exited := make(chan struct{})
	defer close(exited)
	go func() {
		select {
		case <-s.stop:
			iface.Close()
		case <-exited:
		}
	}()

	var errOnce sync.Once
	setError := func(e error) {
		errOnce.Do(func() {
			err = e
		})
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer iface.Close()
		var err error
		for packet := range s.ifaceSend {
			n, e := iface.Write(packet)
			if n < len(packet) && e == nil {
				e = io.ErrShortWrite
			}
			if e != nil {
				err = e
				break
			}
		}
		setError(err)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer iface.Close()
		var err error
		var buf [defaultIfaceReadBufSize]byte
		for {
			n, e := iface.Read(buf[:])
			if n > 0 {
				packet := buf[:n]
				h, e := ipv4.ParseHeader(packet)
				if e != nil {
					log.Printf("failed to parse ipv4 header %v", e)
					continue
				}
				if h.Version != 4 {
					//log.Println("(debug) drop ip version 6")
					continue
				}
				log.Printf("(debug) iface recv: %s", h)
				ss, ok := s.FindSessionByIP(h.Dst)
				if !ok {
					log.Printf("(debug) drop packet to %s: missing session", h.Dst)
					continue
				}
				select {
				case ss.Send <- packet:
				default:
					log.Printf("(debug) drop packet to %s: channel full", h.Dst)
				}
			}
			if e != nil {
				if e != io.EOF {
					err = e
				}
				break
			}
		}
		setError(err)
	}()

	wg.Wait()
	return err
}

// Stop ...
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		close(s.stop)
	})
}

// RequestIP request a ip for client tun interface
func (s *Server) RequestIP(ctx context.Context, req *IPReq) (*IPResp, error) {
	if req.Cid == "" {
		return nil, status.Error(codes.InvalidArgument, "cid empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ss, ok := s.cidSession[req.Cid]
	if ok {
		return &IPResp{Ip: ss.IP.String()}, nil
	}

	ip, ok := s.ippool.Get()
	if !ok {
		return nil, status.Error(codes.ResourceExhausted, "ip exhausted")
	}

	ss = &Session{
		CID:  req.Cid,
		IP:   ip,
		Send: make(chan []byte, defaultSessionSendChanSize),
	}
	s.cidSession[ss.CID] = ss
	s.ipSession[ss.IP.String()] = ss

	return &IPResp{Ip: ss.IP.String()}, nil
}

// Open a tunnel
func (s *Server) Open(stream ServerStream) error {
	cid, err := getMetaClientID(stream.Context())
	if err != nil {
		return err
	}
	ss, ok := s.FindSessionByCID(cid)
	if !ok {
		return status.Error(codes.DataLoss, "session not found")
	}

	go func() {
		// TODO write 出错如何处理?
		for {
			select {
			case pkt, ok := <-ss.Send:
				if !ok {
					return
				}
				err := stream.Send(&Packet{Data: pkt})
				if err != nil {
					log.Println(err)
					return
				}
			case <-stream.Context().Done():
				return
			}
		}
	}()

	for {
		pkt, err := stream.Recv()
		if err != nil {
			return err
		}
		h, err := ipv4.ParseHeader(pkt.Data)
		if err != nil {
			return err
		}
		log.Printf("(debug) conn recv: %s", h)
		if !h.Src.Equal(ss.IP) {
			log.Printf("(debug) drop packet from %s: src (%s) mismatched", ss.IP, h.Src)
			continue
		}
		select {
		// TODO iface serve 异常退出后, ifaceSend 阻塞
		case s.ifaceSend <- pkt.Data:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func getMetaClientID(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Errorf(codes.InvalidArgument, "missing meta %s", metaClientID)
	}
	data := md.Get(metaClientID)
	if len(data) == 0 {
		return "", status.Errorf(codes.InvalidArgument, "missing meta %s", metaClientID)
	}
	id := strings.TrimSpace(data[0])
	if id == "" {
		return "", status.Errorf(codes.InvalidArgument, "missing meta %s", metaClientID)
	}
	return id, nil
}
