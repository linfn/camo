package camo // import "github.com/linfn/camo"

import (
	"context"
	"io"
	"sync"
)

// DefaultMTU TODO
const DefaultMTU = 1400

const (
	headerClientID = "camo-client-id"
)

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
