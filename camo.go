package camo // import "github.com/linfn/camo"

import (
	"context"
	"hash/adler32"
	"io"
	"sync"
)

// DefaultMTU TODO
const DefaultMTU = 1400

const (
	headerClientID = "camo-client-id"
	headerNoise    = "camo-noise"
)

const noisePadding = "BYLtpGfhBnrxe2rC7rbZ5QMHMMIjcMeThMI309QI5Zewv9OD1UNhie2ZPmIEuJDeKeQboeo5ClAwLusaKasWVLIGHkJmY3l0YP2dsoT1MyPSLqb7bAyhetxywAWNzDif"

// code from https://gist.github.com/badboy/6267743
func hash32(a uint32) uint32 {
	a = (a + 0x7ed55d16) + (a << 12)
	a = (a ^ 0xc761c23c) ^ (a >> 19)
	a = (a + 0x165667b1) + (a << 5)
	a = (a + 0xd3a2646c) ^ (a << 9)
	a = (a + 0xfd7046c5) + (a << 3)
	a = (a ^ 0xb55a4f09) ^ (a >> 16)
	return a
}

func getNoisePadding(noise int, url string) string {
	size := hash32(uint32(noise)+adler32.Checksum([]byte(url))) % uint32(len(noisePadding))
	if size == 0 {
		size = 1
	}
	return noisePadding[:size]
}

type packetBuffer struct {
	Data []byte
}

func (p *packetBuffer) Reset() {
	p.Data = p.Data[:cap(p.Data)]
}

type bufferPool interface {
	getBuffer() *packetBuffer
	freeBuffer(*packetBuffer)
}

type (
	readPacketHandler      func(done <-chan struct{}, pkt *packetBuffer) bool
	postWritePacketHandler func(done <-chan struct{}, err error)
)

func serveIO(ctx context.Context, rw io.ReadWriteCloser, bp bufferPool, readHandler readPacketHandler, toWrite <-chan *packetBuffer, postWriteHandler postWritePacketHandler) (err error) {
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
			case p, ok := <-toWrite:
				if !ok {
					return
				}
				_, e := rw.Write(p.Data)
				bp.freeBuffer(p)
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
		p := bp.getBuffer()
		n, e := rw.Read(p.Data)
		if n > 0 {
			p.Data = p.Data[:n]
			ok := readHandler(done, p)
			if !ok {
				bp.freeBuffer(p)
			}
		} else {
			bp.freeBuffer(p)
		}
		if e != nil {
			exit(e)
			break
		}
	}

	wg.Wait()
	return err
}
