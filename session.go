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

	mu           sync.Mutex
	done         bool
	refCount     int
	onRetained   func()
	onReleased   func()
	retainedTime time.Time
	releasedTime time.Time
}

func (s *session) retain() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return false
	}
	s.refCount++
	if s.refCount == 1 {
		s.retainedTime = time.Now()
		if s.onRetained != nil {
			s.onRetained()
		}
	}
	return true
}

func (s *session) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refCount--
	if s.refCount == 0 {
		s.releasedTime = time.Now()
		if s.onReleased != nil {
			s.onReleased()
		}
	}
}

func (s *session) setDone() (ok bool) {
	s.mu.Lock()
	if s.refCount <= 0 {
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
