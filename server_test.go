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

func TestServer_RequestIP(t *testing.T) {
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

	checkIsIPv4 := func(ip net.IP) bool {
		return ip.To4() != nil
	}
	checkIsIPv6 := func(ip net.IP) bool {
		return ip.To4() == nil
	}

	tests := []struct {
		name       string
		reqIP      func(cid string) (ip net.IP, mask net.IPMask, ttl time.Duration, err error)
		checkIPVer func(ip net.IP) bool
		mask       net.IPMask
	}{
		{"v4", srv.RequestIPv4, checkIsIPv4, net.CIDRMask(24, 32)},
		{"v6", srv.RequestIPv6, checkIsIPv6, net.CIDRMask(64, 128)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip1, mask1, _, err := tt.reqIP("camo1")
			if err != nil {
				t.Fatal(err)
			}
			if !tt.checkIPVer(ip1) {
				t.Fatal("wrong ip version")
			}
			if mask1.String() != tt.mask.String() {
				t.Fatal("wrong ip mask")
			}

			ip11, mask11, _, err := tt.reqIP("camo1")
			if err != nil {
				t.Fatal(err)
			}
			if !ip1.Equal(ip11) {
				t.Error("Assign the different IP addresses to the same client")
			}
			if mask1.String() != mask11.String() {
				t.Fatal("Assign the different IP Mask to the same ip address")
			}

			ip2, _, _, err := tt.reqIP("camo2")
			if err != nil {
				t.Fatal(err)
			}
			if ip1.Equal(ip2) {
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
		reqIP       func(cid string) (ip net.IP, mask net.IPMask, ttl time.Duration, err error)
		specifiedIP net.IP
		pkt         func(src net.IP) []byte
	}{
		{"v4", srv.RequestIPv4, net.ParseIP("10.20.0.3"), func(src net.IP) []byte { return newTestIPv4Packet(src, net.ParseIP("10.20.0.1")) }},
		{"v6", srv.RequestIPv6, net.ParseIP("fc00:ca::3"), func(src net.IP) []byte { return newTestIPv6Packet(src, net.ParseIP("fc00:ca::1")) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip1, _, _, err := tt.reqIP("camo1")
			if err != nil {
				t.Fatal(err)
			}

			var closeOnce sync.Once
			rw, peer := newBidirectionalStream()
			defer func() {
				closeOnce.Do(func() { rw.Close() })
			}()

			tunnel, err := srv.OpenTunnel(ip1, "camo1", peer)
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

			_, err = rw.Write(tt.pkt(ip1))
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

			_, err = srv.OpenTunnel(ip1, "camo2", peer2)
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
	srv := Server{
		IPv4Pool: NewSubnetIPPool(&net.IPNet{
			IP:   net.ParseIP("10.20.0.1"),
			Mask: net.CIDRMask(24, 32),
		}, 255),
		IPv6Pool: NewSubnetIPPool(&net.IPNet{
			IP:   net.ParseIP("fc00:ca::1"),
			Mask: net.CIDRMask(64, 128),
		}, 255),
		SessionTTL: time.Nanosecond,
	}

	sessionRemovedChan := make(chan struct{})
	testHookSessionRemoved = func(*session) {
		sessionRemovedChan <- struct{}{}
	}
	defer func() { testHookSessionRemoved = nil }()

	tests := []struct {
		name  string
		reqIP func(cid string) (ip net.IP, mask net.IPMask, ttl time.Duration, err error)
	}{
		{"v4", srv.RequestIPv4},
		{"v6", srv.RequestIPv6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := tt.reqIP("camo1")
			if err != nil {
				t.Fatal(err)
			}
			<-sessionRemovedChan
		})
	}
}
