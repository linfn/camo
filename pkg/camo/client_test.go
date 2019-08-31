package camo

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"

	"github.com/linfn/camo/pkg/util"
	"github.com/lucas-clemente/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func startTestServer(ctx context.Context, t *testing.T, srv *Server) (addr string) {
	go func() {
		err := srv.ServeIface(ctx, newIfaceIOMock())
		if err != nil && ctx.Err() == nil {
			t.Error(err)
		}
	}()

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}

	hsrv := &http.Server{Handler: h2c.NewHandler(srv.Handler(ctx, ""), &http2.Server{})}
	go func() { _ = hsrv.Serve(l) }()

	go func() {
		<-ctx.Done()
		hsrv.Close()
	}()

	return l.Addr().String()
}

func TestClient_RequestIP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvAddr := startTestServer(ctx, t, newTestServer())

	c := Client{
		CID:    "camo1",
		Host:   srvAddr,
		UseH2C: true,
	}

	checkIsIPv4 := func(ip net.IP) bool {
		return ip.To4() != nil
	}
	checkIsIPv6 := func(ip net.IP) bool {
		return ip.To4() == nil
	}

	tests := []struct {
		name       string
		reqIP      func(ctx context.Context) (*IPResult, error)
		checkIPVer func(ip net.IP) bool
		mask       net.IPMask
	}{
		{"v4", c.RequestIPv4, checkIsIPv4, net.CIDRMask(24, 32)},
		{"v6", c.RequestIPv6, checkIsIPv6, net.CIDRMask(64, 128)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := tt.reqIP(ctx)
			if err != nil {
				t.Error(err)
			}
			if !tt.checkIPVer(res.IP) {
				t.Fatal("wrong ip version")
			}
			if res.Mask.String() != tt.mask.String() {
				t.Fatal("wrong ip mask")
			}
		})
	}
}

func TestClient_CreateTunnel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvAddr := startTestServer(ctx, t, newTestServer())

	c := Client{
		CID:    "camo1",
		Host:   srvAddr,
		UseH2C: true,
	}

	tests := []struct {
		name  string
		reqIP func(ctx context.Context) (*IPResult, error)
		pkt   func(src net.IP) []byte
	}{
		{"v4", c.RequestIPv4, func(src net.IP) []byte { return newTestIPv4Packet(src, net.ParseIP("10.20.0.1")) }},
		{"v6", c.RequestIPv6, func(src net.IP) []byte { return newTestIPv6Packet(src, net.ParseIP("fc00:ca::1")) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			res, err := tt.reqIP(ctx)
			if err != nil {
				t.Fatal(err)
			}

			tunnel, err := c.CreateTunnel(ctx, res.IP)
			if err != nil {
				t.Fatal(err)
			}

			var wg sync.WaitGroup

			wg.Add(1)
			go func() {
				defer wg.Done()
				err := tunnel(ctx)
				if err != nil && ctx.Err() == nil {
					t.Error(err)
				}
			}()

			rw, peer := newBidirectionalStream()
			defer rw.Close()

			wg.Add(1)
			go func() {
				defer wg.Done()
				err := c.ServeIface(ctx, peer)
				if err != nil && ctx.Err() == nil {
					t.Error(err)
				}
			}()

			_, err = rw.Write(tt.pkt(res.IP))
			if err != nil {
				t.Fatal(err)
			}

			var recvBuf [DefaultMTU]byte
			_, err = ReadIPPacket(rw, recvBuf[:])
			if err != nil {
				t.Error(err)
			}

			cancel()
			wg.Wait()
		})
	}
}

func TestClient_Noise(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := newTestServer()
	srv.Noise = 1
	srvAddr := startTestServer(ctx, t, srv)

	c := Client{
		CID:    "camo1",
		Host:   srvAddr,
		UseH2C: true,
		Noise:  2,
	}

	testHookClientDoReq = func(req *http.Request, res *http.Response, err error) {
		if err != nil {
			t.Error(err)
			return
		}
		if len(req.Header.Get(headerNoise)) == 0 {
			t.Errorf("request missing noise header. url: %s %s", req.Method, req.URL.Path)
		} else {
			t.Logf("request noise padding size: %d", len(req.Header.Get(headerNoise)))
		}
		if len(res.Header.Get(headerNoise)) == 0 {
			t.Errorf("response missing noise header. url: %s %s", req.Method, req.URL.Path)
		} else {
			t.Logf("response noise padding size: %d", len(res.Header.Get(headerNoise)))
		}
	}
	defer func() { testHookClientDoReq = nil }()

	res, _ := c.RequestIPv4(ctx)
	_, err := c.RequestIPv6(ctx)
	if err != nil {
		t.Error(err)
	}
	_, err = c.CreateTunnel(ctx, res.IP)
	if err != nil {
		t.Error(err)
	}
}

func startTestH3Server(ctx context.Context, t *testing.T, srv *Server) (addr string) {
	go func() {
		err := srv.ServeIface(ctx, newIfaceIOMock())
		if err != nil && ctx.Err() == nil {
			t.Error(err)
		}
	}()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}

	h3 := http3.Server{
		Server: &http.Server{
			TLSConfig: &tls.Config{
				SessionTicketKey: NewSessionTicketKey("camotest"),
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					return nil, errors.New("(PSK) bad certificate")
				},
			},
			Handler: srv.Handler(ctx, ""),
		},
	}
	go func() { _ = h3.Serve(conn) }()

	go func() {
		<-ctx.Done()
		h3.Close()
	}()

	return conn.LocalAddr().String()
}

func TestH3(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvAddr := startTestH3Server(ctx, t, newTestServer())

	cs, err := NewTLSPSKSessionCache(util.StripPort(srvAddr), NewSessionTicketKey("camotest"))
	if err != nil {
		t.Fatal(err)
	}
	c := Client{
		CID:  "camo1",
		Host: srvAddr,
		TLSConfig: &tls.Config{
			ServerName:         util.StripPort(srvAddr),
			ClientSessionCache: cs,
		},
		UseH3: true,
	}

	res, err := c.RequestIPv4(ctx)
	if err != nil {
		t.Fatal(err)
	}

	tunnel, err := c.CreateTunnel(ctx, res.IP)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := tunnel(ctx)
		if err != nil && ctx.Err() == nil {
			t.Error(err)
		}
	}()

	rw, peer := newBidirectionalStream()
	defer rw.Close()

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := c.ServeIface(ctx, peer)
		if err != nil && ctx.Err() == nil {
			t.Error(err)
		}
	}()

	_, err = rw.Write(newTestIPv4Packet(res.IP, net.ParseIP("10.20.0.1")))
	if err != nil {
		t.Fatal(err)
	}

	var recvBuf [DefaultMTU]byte
	_, err = ReadIPPacket(rw, recvBuf[:])
	if err != nil {
		t.Error(err)
	}
}
