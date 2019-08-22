package camo

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// DefaultMTU TODO
const DefaultMTU = 1400

var (
	errBadPacketRead = errors.New("bad packet read")
)

func parseIPv4Header(h *ipv4.Header, b []byte) error {
	err := h.Parse(b)
	if err != nil {
		return err
	}
	// golang.org/x/net/ipv4 Parse use raw IP socket format, tuntap use wire format
	h.TotalLen = int(binary.BigEndian.Uint16(b[2:4]))
	h.FragOff = int(binary.BigEndian.Uint16(b[6:8]))
	return nil
}

func getVersion(b []byte) int {
	return int(b[0] >> 4)
}
func getIPv4TotalLen(b []byte) int {
	return int(binary.BigEndian.Uint16(b[2:4]))
}
func getIPv6TotalLen(b []byte) int {
	// how to handle jumbo frame?
	return int(binary.BigEndian.Uint16(b[4:6])) + ipv6.HeaderLen
}

type packetIO struct {
	rw io.ReadWriteCloser
}

func (p *packetIO) Read(b []byte) (int, error) {
	if len(b) < ipv4.HeaderLen {
		return 0, io.ErrShortBuffer
	}
	n, err := io.ReadFull(p.rw, b[:ipv4.HeaderLen])
	if err != nil {
		return 0, err
	}
	var totalLen int
	switch getVersion(b) {
	case 4:
		totalLen = getIPv4TotalLen(b)
		if totalLen < ipv4.HeaderLen {
			return 0, errBadPacketRead
		}
	case 6:
		totalLen = getIPv6TotalLen(b)
	default:
		return 0, errBadPacketRead
	}
	if totalLen > len(b) {
		return 0, io.ErrShortBuffer
	}
	_, err = io.ReadFull(p.rw, b[n:totalLen])
	if err != nil {
		return 0, err
	}
	return totalLen, nil
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
