package camo

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

const (
	defaultIfaceSendChanSize   = 256
	defaultSessionSendChanSize = 256
)

var (
	// ErrNoIPv4Config ...
	ErrNoIPv4Config = Error(http.StatusBadRequest, "server no ipv4 config")
	// ErrIPExhausted ...
	ErrIPExhausted = Error(http.StatusServiceUnavailable, "ip exhausted")
	// ErrSessionNotFound ...
	ErrSessionNotFound = Error(http.StatusBadRequest, "session not found")
)

// Server ...
type Server struct {
	MTU      int
	IPv4Pool *IPPool

	mu         sync.RWMutex
	cidSession map[string]*Session
	ipSession  map[string]*Session

	bufPool       sync.Pool
	ifaceSendChan chan bufPacket
	doneChan      chan struct{}
}

type bufPacket struct {
	b []byte
	n int
}

func (s *Server) getIfaceSendChan() chan bufPacket {
	s.mu.RLock()
	if s.ifaceSendChan != nil {
		s.mu.RUnlock()
		return s.ifaceSendChan
	}
	s.mu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ifaceSendChan == nil {
		s.ifaceSendChan = make(chan bufPacket, defaultIfaceSendChanSize)
	}
	return s.ifaceSendChan
}

func (s *Server) getDoneChan() chan struct{} {
	s.mu.RLock()
	if s.doneChan != nil {
		s.mu.RUnlock()
		return s.doneChan
	}
	s.mu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.doneChan == nil {
		s.doneChan = make(chan struct{})
	}
	return s.doneChan
}

func (s *Server) mtu() int {
	if s.MTU <= 0 {
		return DefaultMTU
	}
	return s.MTU
}

func (s *Server) getBuffer() []byte {
	b := s.bufPool.Get()
	if b == nil {
		return make([]byte, s.mtu())
	}
	return b.([]byte)
}

func (s *Server) freeBuffer(b []byte) {
	s.bufPool.Put(b)
}

// Serve ...
func (s *Server) Serve(iface io.ReadWriteCloser) (err error) {
	// 确保 exit 的 default part 在 Serve 函数内部一定会被执行
	done := make(chan struct{})
	exit := func(e error) {
		select {
		case <-done:
		default:
			close(done)
			err = e
			iface.Close()
		}
	}

	go func() {
		srvDone := s.getDoneChan()
		select {
		case <-srvDone:
			exit(nil)
		case <-done:
		}
	}()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		ifaceSend := s.getIfaceSendChan()
		for {
			select {
			case pkt, ok := <-ifaceSend:
				if !ok {
					exit(nil)
					return
				}
				_, e := iface.Write(pkt.b[:pkt.n])
				s.freeBuffer(pkt.b)
				if e != nil {
					exit(e)
					return
				}
			case <-done:
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		var h ipv4.Header
		for {
			buf := s.getBuffer()
			freeBuf := true
			n, e := iface.Read(buf)
			if n > 0 {
				e := parseIPv4Header(&h, buf[:n])
				if e != nil {
					log.Printf("(debug) iface failed to parse ipv4 header %v", e)
					goto ERR
				}
				if h.Version != 4 {
					//log.Println("(debug) drop ip version 6")
					goto ERR
				}
				log.Printf("(debug) iface recv: %s", &h)
				ss, ok := s.findSessionByIP(h.Dst)
				if !ok {
					log.Printf("(debug) iface drop packet to %s: missing session", h.Dst)
					goto ERR
				}
				select {
				case ss.send <- bufPacket{buf, n}:
					freeBuf = false
				default:
					log.Printf("(debug) iface drop packet to %s: channel full", h.Dst)
				}
			}
		ERR:
			if freeBuf {
				s.freeBuffer(buf)
			}
			if e != nil {
				if e == io.EOF {
					e = nil
				}
				exit(e)
				return
			}
		}
	}()

	wg.Wait()
	return
}

// Close ...
func (s *Server) Close() {
	done := s.getDoneChan()
	select {
	case <-done:
	default:
		close(done)
	}
}

// RequestIPv4 ...
func (s *Server) RequestIPv4(cid string, reqIP net.IP) (ip net.IP, ttl time.Duration, err error) {
	if cid == "" {
		err = Error(http.StatusBadRequest, "empty cid")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cidSession == nil {
		s.cidSession = make(map[string]*Session)
		s.ipSession = make(map[string]*Session)
	}

	ss, ok := s.cidSession[cid]
	if ok {
		return ss.ipv4, 0, nil
	}

	if s.IPv4Pool == nil {
		err = ErrNoIPv4Config
		return
	}

	ip, ok = s.IPv4Pool.Get()
	if !ok {
		err = ErrIPExhausted
		return
	}

	ss = &Session{
		cid:  cid,
		ipv4: ip,
		send: make(chan bufPacket, defaultSessionSendChanSize),
	}
	s.cidSession[ss.cid] = ss
	s.ipSession[ss.ipv4.String()] = ss

	return ip, 0, nil
}

// Tunnel ...
func (s *Server) Tunnel(cid string, rw io.ReadWriteCloser) (err error) {
	ss, ok := s.findSessionByCID(cid)
	if !ok {
		rw.Close()
		return ErrSessionNotFound
	}

	// for flush
	rw.Write(nil)

	done := make(chan struct{})
	exit := func(e error) {
		select {
		case <-done:
		default:
			close(done)
			err = e
			rw.Close()
		}
	}

	go func() {
		srvDone := s.getDoneChan()
		select {
		case <-srvDone:
			exit(nil)
		case <-done:
		}
	}()

	go func() {
		for {
			select {
			case pkt, ok := <-ss.send:
				if !ok {
					exit(nil)
					return
				}
				_, e := writePacket(rw, pkt.b[:pkt.n])
				s.freeBuffer(pkt.b)
				if e != nil {
					exit(e)
					return
				}
			case <-done:
				return
			}
		}
	}()

	ifaceSend := s.getIfaceSendChan()
	var h ipv4.Header
	for {
		buf := s.getBuffer()
		freeBuf := true
		n, e := readPacket(buf, &h, rw)
		if n > 0 {
			log.Printf("(debug) conn recv: %s", &h)
			if !h.Src.Equal(ss.ipv4) {
				log.Printf("(debug) conn drop packet from %s: src (%s) mismatched", ss.ipv4, h.Src)
				goto ERR
			}
			select {
			case ifaceSend <- bufPacket{buf, n}:
				freeBuf = false
			case <-done:
				s.freeBuffer(buf)
				return
			}
		}
	ERR:
		if freeBuf {
			s.freeBuffer(buf)
		}
		if e != nil {
			if e != io.EOF {
				e = nil
			} else {
				e = fmt.Errorf("conn read packet error: %v", e)
			}
			exit(e)
			return
		}
	}
}

// Handler ...
func (s *Server) Handler(prefix string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(prefix+"/ip/v4", http.RedirectHandler(prefix+"/ip/v4/", http.StatusPermanentRedirect))
	mux.HandleFunc(prefix+"/ip/v4/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, prefix+"/ip/v4/")
		if strings.Contains(path, "/") {
			http.NotFound(w, r)
			return
		}
		if r.Method != "POST" {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		var reqIP net.IP
		if ip := path; len(ip) > 0 {
			reqIP = net.ParseIP(ip)
			if reqIP == nil {
				http.Error(w, "Invalid ip", http.StatusBadRequest)
				return
			}
		}

		var reqBody struct {
			CID string `json:"cid"`
		}
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} else if reqBody.CID == "" {
			http.Error(w, "Empty cid", http.StatusBadRequest)
			return
		}

		ip, ttl, err := s.RequestIPv4(reqBody.CID, reqIP)
		if err != nil {
			http.Error(w, err.Error(), GetStatusCode(err))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(&struct {
			IP  string `json:"ip"`
			TTL int    `json:"ttl"`
		}{
			IP:  ip.String(),
			TTL: int(ttl / time.Second),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc(prefix+"/tunnel/", func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			http.Error(w, "HTTP/2.0 required", http.StatusUpgradeRequired)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, prefix+"/tunnel/")
		if strings.Contains(path, "/") {
			http.NotFound(w, r)
			return
		}
		if r.Method != "POST" {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		cid := path
		if cid == "" {
			http.Error(w, "Empty cid", http.StatusBadRequest)
			return
		}

		err := s.Tunnel(cid, &httpReadWriteCloser{r.Body, w})
		if err != nil {
			http.Error(w, err.Error(), GetStatusCode(err))
			return
		}
	})

	return mux
}

type httpReadWriteCloser struct {
	io.ReadCloser
	w io.Writer
}

func (h *httpReadWriteCloser) Write(b []byte) (int, error) {
	n, err := h.w.Write(b)
	if f, ok := h.w.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}
