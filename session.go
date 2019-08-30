package camo

import (
	"net"
	"sync"
	"time"
)

type session struct {
	cid        string
	ip         net.IP
	mask       net.IPMask
	gw         net.IP
	writeChan  chan []byte
	createTime time.Time

	mu    sync.Mutex
	done  bool
	owner chan struct{}

	onRetained   func()
	onReleased   func()
	retainedTime time.Time
	releasedTime time.Time
}

func (s *session) retain() (release func(), robbed <-chan struct{}, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return
	}

	if s.owner != nil {
		s.releaseLocked()
	}

	owner := make(chan struct{})
	s.owner = owner
	s.retainedTime = time.Now()
	if s.onRetained != nil {
		s.onRetained()
	}

	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.owner == owner {
			s.releaseLocked()
		}
	}, owner, true
}

func (s *session) releaseLocked() {
	close(s.owner)
	s.owner = nil
	s.releasedTime = time.Now()
	if s.onReleased != nil {
		s.onReleased()
	}
}

func (s *session) trySetDone() (ok bool) {
	s.mu.Lock()
	if s.owner == nil {
		s.done = true
		ok = true
	}
	s.mu.Unlock()
	return ok
}

func (s *session) idleDuration() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retainedTime.After(s.retainedTime) {
		return 0
	}
	if !s.releasedTime.IsZero() {
		return time.Now().Sub(s.releasedTime)
	}
	return time.Now().Sub(s.createTime)
}
