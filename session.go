package camo

import "net"

// Session ...
type Session struct {
	cid  string
	ipv4 net.IP
	send chan bufPacket
}

func (s *Server) findSessionByCID(cid string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ss, ok := s.cidSession[cid]
	return ss, ok
}

func (s *Server) findSessionByIP(ip net.IP) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ss, ok := s.ipSession[ip.String()]
	return ss, ok
}
