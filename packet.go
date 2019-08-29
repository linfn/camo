package camo

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// DefaultMTU TODO
const DefaultMTU = 1400

const (
	// IPv4HeaderLen is IPv4 header length without extension headers
	IPv4HeaderLen = 20
	// IPv6HeaderLen is IPv6 header length without extension headers
	IPv6HeaderLen = 40
)

// GetIPPacketVersion gets ip protocol version from ip packet
func GetIPPacketVersion(b []byte) int {
	return int(b[0] >> 4)
}

// IPv4Header represents an IPv4 header
type IPv4Header []byte

// Version is protocol version
func (b IPv4Header) Version() int {
	return int(b[0] >> 4)
}

// Len is header length
func (b IPv4Header) Len() int {
	return int(b[0]&0x0f) << 2
}

// TOS is type-of-service
func (b IPv4Header) TOS() int {
	return int(b[1])
}

// TotalLen is packet total length
func (b IPv4Header) TotalLen() int {
	return int(binary.BigEndian.Uint16(b[2:4]))
}

// ID is identification
func (b IPv4Header) ID() int {
	return int(binary.BigEndian.Uint16(b[4:6]))
}

// Flags is IPv4 flags
func (b IPv4Header) Flags() int {
	return (int(binary.BigEndian.Uint16(b[6:8])) & 0xe000) >> 13
}

// FragOff is fragment offset
func (b IPv4Header) FragOff() int {
	return int(binary.BigEndian.Uint16(b[6:8])) & 0x1fff
}

// TTL is time-to-live
func (b IPv4Header) TTL() int {
	return int(b[8])
}

// Protocol is next protocol
func (b IPv4Header) Protocol() int {
	return int(b[9])
}

// Checksum is IPv4 header checksum
func (b IPv4Header) Checksum() int {
	return int(binary.BigEndian.Uint16(b[10:12]))
}

// Src is source address
func (b IPv4Header) Src() net.IP {
	return net.IP(b[12:16])
}

// Dst is destination address
func (b IPv4Header) Dst() net.IP {
	return net.IP(b[16:20])
}

// Options is extension headers
func (b IPv4Header) Options() []byte {
	hdrlen := b.Len()
	if hdrlen > IPv4HeaderLen {
		if len(b) >= hdrlen {
			return b[IPv4HeaderLen:hdrlen]
		}
		return b[IPv4HeaderLen:]
	}
	return nil
}

func (b IPv4Header) String() string {
	return fmt.Sprintf("ver=%d hdrlen=%d tos=%#x totallen=%d id=%#x flags=%#x fragoff=%#x ttl=%d proto=%d cksum=%#x src=%v dst=%v", b.Version(), b.Len(), b.TOS(), b.TotalLen(), b.ID(), b.Flags(), b.FragOff(), b.TTL(), b.Protocol(), b.Checksum(), b.Src(), b.Dst())
}

// IPv6Header represents an IPv6 base header
type IPv6Header []byte

// Version is protocol version
func (b IPv6Header) Version() int {
	return int(b[0]) >> 4
}

// TrafficClass is traffic class
func (b IPv6Header) TrafficClass() int {
	return int(b[0]&0x0f)<<4 | int(b[1])>>4
}

// FlowLabel is flow label
func (b IPv6Header) FlowLabel() int {
	return int(b[1]&0x0f)<<16 | int(b[2])<<8 | int(b[3])
}

// PayloadLen is payload length
func (b IPv6Header) PayloadLen() int {
	return int(binary.BigEndian.Uint16(b[4:6]))
}

// NextHeader is next header
func (b IPv6Header) NextHeader() int {
	return int(b[6])
}

// HopLimit is hop limit
func (b IPv6Header) HopLimit() int {
	return int(b[7])
}

// Src is source address
func (b IPv6Header) Src() net.IP {
	return net.IP(b[8:24])
}

// Dst is destination address
func (b IPv6Header) Dst() net.IP {
	return net.IP(b[24:40])
}

func (b IPv6Header) String() string {
	return fmt.Sprintf("ver=%d tclass=%#x flowlbl=%#x payloadlen=%d nxthdr=%d hoplim=%d src=%v dst=%v", b.Version(), b.TrafficClass(), b.FlowLabel(), b.PayloadLen(), b.NextHeader(), b.HopLimit(), b.Src(), b.Dst())
}

var errBadPacketRead = errors.New("bad packet read")

// ReadIPPacket reads a IPv4/IPv6 packet from the io.Reader
func ReadIPPacket(r io.Reader, b []byte) (int, error) {
	if len(b) < IPv4HeaderLen {
		return 0, io.ErrShortBuffer
	}
	n, err := io.ReadFull(r, b[:IPv4HeaderLen])
	if err != nil {
		return 0, err
	}
	var totalLen int
	switch GetIPPacketVersion(b) {
	case 4:
		totalLen = IPv4Header(b).TotalLen()
		if totalLen < IPv4HeaderLen {
			return 0, errBadPacketRead
		}
	case 6:
		// how to handle jumbo frame?
		totalLen = IPv6Header(b).PayloadLen() + IPv6HeaderLen
	default:
		return 0, errBadPacketRead
	}
	if totalLen > len(b) {
		return 0, io.ErrShortBuffer
	}
	_, err = io.ReadFull(r, b[n:totalLen])
	if err != nil {
		return 0, err
	}
	return totalLen, nil
}

type packetIO struct {
	rw io.ReadWriteCloser
}

func (p *packetIO) Read(b []byte) (int, error) {
	return ReadIPPacket(p.rw, b)
}

func (p *packetIO) Write(b []byte) (int, error) {
	return p.rw.Write(b)
}

func (p *packetIO) Close() error {
	return p.rw.Close()
}

type bufferPool interface {
	getBuffer() []byte
	freeBuffer([]byte)
}

type (
	readPacketHandler      func(done <-chan struct{}, pkt []byte) bool
	postWritePacketHandler func(done <-chan struct{}, err error)
)

func serveIO(ctx context.Context, rw io.ReadWriteCloser, bp bufferPool, readHandler readPacketHandler, toWrite <-chan []byte, postWriteHandler postWritePacketHandler) (err error) {
	ctx, cancel := context.WithCancel(ctx)

	var exitOnce sync.Once
	exit := func(e error) {
		exitOnce.Do(func() {
			err = e
			rw.Close()
			cancel()
		})
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		exit(ctx.Err())
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		done := ctx.Done()
		for {
			select {
			case pkt, ok := <-toWrite:
				if !ok {
					return
				}
				_, e := rw.Write(pkt)
				bp.freeBuffer(pkt)
				if postWriteHandler != nil {
					postWriteHandler(done, e)
				}
				if e != nil {
					exit(e)
					return
				}
			case <-done:
				return
			}
		}
	}()

	done := ctx.Done()
	for {
		b := bp.getBuffer()
		n, e := rw.Read(b)
		if n > 0 {
			ok := readHandler(done, b[:n])
			if !ok {
				bp.freeBuffer(b)
			}
		} else {
			bp.freeBuffer(b)
		}
		if e != nil {
			exit(e)
			break
		}
	}

	wg.Wait()
	return
}
