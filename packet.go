package camo

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// DefaultMTU TODO
const DefaultMTU = 1500

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

func serveIO(stop <-chan struct{}, rw io.ReadWriteCloser, bp bufferPool, toWrite <-chan []byte, handler func(stop <-chan struct{}, pkt []byte) (bool, error)) (err error) {
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
		select {
		case <-stop:
			exit(nil)
		case <-done:
		}
	}()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case pkt, ok := <-toWrite:
				if !ok {
					bp.freeBuffer(pkt)
					exit(nil)
					return
				}
				_, e := rw.Write(pkt)
				bp.freeBuffer(pkt)
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
		for {
			b := bp.getBuffer()
			n, e := rw.Read(b)
			if n > 0 {
				ok, e := handler(done, b[:n])
				if !ok {
					bp.freeBuffer(b)
				}
				if e != nil {
					exit(e)
					return
				}
			} else {
				bp.freeBuffer(b)
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
