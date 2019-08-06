package camo

import "net"

// Session ...
type Session struct {
	CID  string
	IP   net.IP
	Send chan []byte
}

// FindSessionByCID ...
func (s *Server) FindSessionByCID(cid string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ss, ok := s.cidSession[cid]
	return ss, ok
}

// FindSessionByIP ...
func (s *Server) FindSessionByIP(ip net.IP) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ss, ok := s.ipSession[ip.String()]
	return ss, ok
}
