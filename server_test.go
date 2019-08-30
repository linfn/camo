package camo

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func newTestServer() *Server {
	return &Server{
		IPv4Pool: NewSubnetIPPool(&net.IPNet{
			IP:   net.ParseIP("10.20.0.0"),
			Mask: net.CIDRMask(24, 32),
		}, net.ParseIP("10.20.0.1"), 255),
		IPv6Pool: NewSubnetIPPool(&net.IPNet{
			IP:   net.ParseIP("fc00:ca::"),
			Mask: net.CIDRMask(64, 128),
		}, net.ParseIP("fc00:ca::1"), 255),
	}
}

func TestServer_RequestIP(t *testing.T) {
	srv := newTestServer()

	checkIsIPv4 := func(ip net.IP) bool {
		return ip.To4() != nil
	}
	checkIsIPv6 := func(ip net.IP) bool {
		return ip.To4() == nil
	}

	tests := []struct {
		name       string
		reqIP      func(cid string) (*IPResult, error)
		checkIPVer func(ip net.IP) bool
		mask       net.IPMask
	}{
		{"v4", srv.RequestIPv4, checkIsIPv4, net.CIDRMask(24, 32)},
		{"v6", srv.RequestIPv6, checkIsIPv6, net.CIDRMask(64, 128)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res1, err := tt.reqIP("camo1")
			if err != nil {
				t.Fatal(err)
			}
			if !tt.checkIPVer(res1.IP) {
				t.Fatal("wrong ip version")
			}
			if res1.Mask.String() != tt.mask.String() {
				t.Fatal("wrong ip mask")
			}

			res11, err := tt.reqIP("camo1")
			if err != nil {
				t.Fatal(err)
			}
			if !res1.IP.Equal(res11.IP) {
				t.Error("Assign the different IP addresses to the same client")
			}
			if res1.Mask.String() != res11.Mask.String() {
				t.Fatal("Assign the different IP Mask to the same ip address")
			}

			res2, err := tt.reqIP("camo2")
			if err != nil {
				t.Fatal(err)
			}
			if res1.IP.Equal(res2.IP) {
				t.Error("Assign the same IP address to different clients")
			}
		})
	}
}

func newBidirectionalStream() (io.ReadWriteCloser, io.ReadWriteCloser) {
	type iorwc struct {
		io.Reader
		io.WriteCloser
	}
	sendR, sendW := io.Pipe()
	recvR, recvW := io.Pipe()
	return iorwc{recvR, sendW}, iorwc{sendR, recvW}
}

func newIfaceIOMock() io.ReadWriteCloser {
	rw, peer := newBidirectionalStream()
	go func() {
		defer rw.Close()
		var (
			b [DefaultMTU]byte
		)
		for {
			n, err := ReadIPPacket(rw, b[:])
			if err != nil {
				break
			}
			pkt := b[:n]
			var src, dst net.IP
			if ver := GetIPPacketVersion(pkt); ver == 4 {
				src = IPv4Header(pkt).Src()
				dst = IPv4Header(pkt).Dst()
			} else {
				src = IPv6Header(pkt).Src()
				dst = IPv6Header(pkt).Dst()
			}
			// swap(src, dst)
			for i := range src {
				src[i], dst[i] = dst[i], src[i]
			}
			// ignore checksum fix
			n, err = rw.Write(pkt)
			if err != nil {
				break
			}
		}
	}()
	return peer
}

func newTestIPv4Packet(src, dst net.IP) []byte {
	pkt := IPv4Header(make([]byte, IPv4HeaderLen))
	pkt[0] = byte(4<<4 | (IPv4HeaderLen >> 2 & 0x0f))
	binary.BigEndian.PutUint16(pkt[2:4], uint16(IPv4HeaderLen))
	copy(pkt.Src(), src.To4())
	copy(pkt.Dst(), dst.To4())
	return pkt
}

func newTestIPv6Packet(src, dst net.IP) []byte {
	pkt := IPv6Header(make([]byte, IPv6HeaderLen))
	pkt[0] = byte(6 << 4)
	copy(pkt.Src(), src.To16())
	copy(pkt.Dst(), dst.To16())
	return pkt
}

func TestServer_OpenTunnel(t *testing.T) {
	srv := newTestServer()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		err := srv.ServeIface(ctx, newIfaceIOMock())
		if err != nil && ctx.Err() == nil {
			t.Error(err)
		}
	}()

	tests := []struct {
		name        string
		reqIP       func(cid string) (*IPResult, error)
		specifiedIP net.IP
		pkt         func(src net.IP) []byte
	}{
		{"v4", srv.RequestIPv4, net.ParseIP("10.20.0.3"), func(src net.IP) []byte { return newTestIPv4Packet(src, net.ParseIP("10.20.0.1")) }},
		{"v6", srv.RequestIPv6, net.ParseIP("fc00:ca::3"), func(src net.IP) []byte { return newTestIPv6Packet(src, net.ParseIP("fc00:ca::1")) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res1, err := tt.reqIP("camo1")
			if err != nil {
				t.Fatal(err)
			}

			var closeOnce sync.Once
			rw, peer := newBidirectionalStream()
			defer func() {
				closeOnce.Do(func() { rw.Close() })
			}()

			tunnel, err := srv.OpenTunnel(res1.IP, "camo1", peer)
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			var wg sync.WaitGroup

			wg.Add(1)
			go func() {
				defer wg.Done()
				err := tunnel(ctx)
				if err != nil && ctx.Err() == nil {
					t.Error(err)
				}
			}()

			_, err = rw.Write(tt.pkt(res1.IP))
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

			rw2, peer2 := newBidirectionalStream()
			defer rw2.Close()

			_, err = srv.OpenTunnel(res1.IP, "camo2", peer2)
			if err == nil {
				t.Error("Different clients cannot open the tunnel of the same ip address at the same time.")
			}

			_, err = srv.OpenTunnel(tt.specifiedIP, "camo2", peer2)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func TestServer_SessionTTL(t *testing.T) {
	srv := newTestServer()
	srv.SessionTTL = time.Nanosecond

	sessionRemovedChan := make(chan struct{})
	testHookSessionRemoved = func(*session) {
		sessionRemovedChan <- struct{}{}
	}
	defer func() { testHookSessionRemoved = nil }()

	tests := []struct {
		name  string
		reqIP func(cid string) (*IPResult, error)
	}{
		{"v4", srv.RequestIPv4},
		{"v6", srv.RequestIPv6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.reqIP("camo1")
			if err != nil {
				t.Fatal(err)
			}
			<-sessionRemovedChan
		})
	}
}
