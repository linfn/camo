package camo

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const metaEndpoint = "camo-address"

const (
	defaultDialTimeout = 3 * time.Second
	defaultReadBufSize = 2048
)

type Server struct {
	gs *grpc.Server
}

func NewServer(gs *grpc.Server) *Server {
	s := new(Server)
	s.gs = gs
	RegisterTunnelServer(s.gs, s)
	return s
}

func (s *Server) Serve(l net.Listener) error {
	return s.gs.Serve(l)
}

func (s *Server) Stop() {
	s.gs.GracefulStop()
}

func (s *Server) Connect(stream Tunnel_ConnectServer) error {
	addr, err := getConnectAddress(stream.Context())
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", addr, defaultDialTimeout)
	if err != nil {
		return err
	}

	// from stream to conn
	var closed int32
	var werr error
	go func() {
		defer conn.Close()
		defer atomic.StoreInt32(&closed, 1)
		for {
			pkt, err := stream.Recv()
			if err != nil {
				if err != io.EOF {
					werr = err
				}
				break
			}
			_, err = conn.Write(pkt.Data)
			if err != nil {
				werr = err
				break
			}
		}
	}()

	// from conn to stream
	var rerr error
	var buf [defaultReadBufSize]byte
	for {
		n, err := conn.Read(buf[:])
		if n > 0 || err == nil {
			err = stream.Send(&TCPPacket{
				Data: buf[:n],
			})
			if err != nil {
				rerr = err
				break
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			if ne, ok := err.(net.Error); !ok || !ne.Temporary() {
				rerr = err
				break
			}
		}
	}

	if atomic.LoadInt32(&closed) != 0 {
		return werr
	}
	return rerr
}

func (s *Server) OpenUDP(stream Tunnel_OpenUDPServer) error {
	// TODO udp 转发需要维护一种类似 NAT 的机制
	// 另外在 tcp 上走 udp 感觉太浪费了
	return status.Error(codes.Unimplemented, "Unimplemented")
}

func getConnectAddress(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Errorf(codes.InvalidArgument, "no %s", metaEndpoint)
	}
	address := md.Get(metaEndpoint)
	if len(address) == 0 {
		return "", status.Errorf(codes.InvalidArgument, "no %s", metaEndpoint)
	}
	return address[0], nil
}
