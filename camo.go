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
