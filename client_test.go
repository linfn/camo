package camo

import (
	"context"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func startTestServer(ctx context.Context, t *testing.T) (addr string) {
	srv := Server{
		IPv4Pool: NewSubnetIPPool(&net.IPNet{
			IP:   net.ParseIP("10.20.0.1"),
			Mask: net.CIDRMask(24, 32),
		}, 255),
		IPv6Pool: NewSubnetIPPool(&net.IPNet{
			IP:   net.ParseIP("fc00:ca::1"),
			Mask: net.CIDRMask(64, 128),
		}, 255),
	}

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
	go hsrv.Serve(l)

	go func() {
		<-ctx.Done()
		hsrv.Close()
	}()

	return l.Addr().String()
}

func TestClient_RequestIP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvAddr := startTestServer(ctx, t)

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
		reqIP      func(ctx context.Context) (ip net.IP, mask net.IPMask, ttl time.Duration, err error)
		checkIPVer func(ip net.IP) bool
		mask       net.IPMask
	}{
		{"v4", c.RequestIPv4, checkIsIPv4, net.CIDRMask(24, 32)},
		{"v6", c.RequestIPv6, checkIsIPv6, net.CIDRMask(64, 128)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, mask, _, err := tt.reqIP(ctx)
			if err != nil {
				t.Error(err)
			}
			if !tt.checkIPVer(ip) {
				t.Fatal("wrong ip version")
			}
			if mask.String() != tt.mask.String() {
				t.Fatal("wrong ip mask")
			}
		})
	}
}

func TestClient_OpenTunnel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvAddr := startTestServer(ctx, t)

	c := Client{
		CID:    "camo1",
		Host:   srvAddr,
		UseH2C: true,
	}

	tests := []struct {
		name  string
		reqIP func(ctx context.Context) (ip net.IP, mask net.IPMask, ttl time.Duration, err error)
		pkt   func(src net.IP) []byte
	}{
		{"v4", c.RequestIPv4, func(src net.IP) []byte { return newTestIPv4Packet(src, net.ParseIP("10.20.0.1")) }},
		{"v6", c.RequestIPv6, func(src net.IP) []byte { return newTestIPv6Packet(src, net.ParseIP("fc00:ca::1")) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			ip, _, _, err := tt.reqIP(ctx)
			if err != nil {
				t.Fatal(err)
			}

			tunnel, err := c.OpenTunnel(ctx, ip)
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

			var closeOnce sync.Once
			rw, peer := newBidirectionalStream()
			defer func() {
				closeOnce.Do(func() { rw.Close() })
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				err := c.ServeIface(ctx, peer)
				if err != nil && ctx.Err() == nil {
					t.Error(err)
				}
			}()

			_, err = rw.Write(tt.pkt(ip))
			if err != nil {
				t.Fatal(err)
			}

			var recvBuf [DefaultMTU]byte
			_, err = ReadIPPacket(rw, recvBuf[:])
			if err != nil {
				t.Error(err)
			}

			cancel()
			closeOnce.Do(func() { rw.Close() })
			wg.Wait()
		})
	}
}
