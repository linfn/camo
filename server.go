package camo

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

const headerClientID = "camo-client-id"

const (
	defaultServerIfaceWriteChanLen  = 256
	defaultServerTunnelWriteChanLen = 256
)

var (
	// ErrNoIPv4Config ...
	ErrNoIPv4Config = newError(http.StatusUnprocessableEntity, "no ipv4 config")
	// ErrIPExhausted ...
	ErrIPExhausted = newError(http.StatusServiceUnavailable, "ip exhausted")
	// ErrIPConflict ...
	ErrIPConflict = newError(http.StatusConflict, "ip conflict")
)

// Server ...
type Server struct {
	MTU      int
	IPv4Pool *IPPool
	Logger   Logger

	mu             sync.RWMutex
	ipSession      map[string]*Session
	cidIPv4Session map[string]*Session
	cidIPv6Session map[string]*Session

	bufPool        sync.Pool
	ifaceWriteChan chan []byte
	doneChan       chan struct{}
}

func (s *Server) getIfaceWriteChan() chan []byte {
	s.mu.RLock()
	if s.ifaceWriteChan != nil {
		s.mu.RUnlock()
		return s.ifaceWriteChan
	}
	s.mu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ifaceWriteChan == nil {
		s.ifaceWriteChan = make(chan []byte, defaultServerIfaceWriteChanLen)
	}
	return s.ifaceWriteChan
}

func (s *Server) getDoneChan() chan struct{} {
	s.mu.RLock()
	if s.doneChan != nil {
		s.mu.RUnlock()
		return s.doneChan
	}
	s.mu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.doneChan == nil {
		s.doneChan = make(chan struct{})
	}
	return s.doneChan
}

func (s *Server) mtu() int {
	if s.MTU <= 0 {
		return DefaultMTU
	}
	return s.MTU
}

func (s *Server) getBuffer() []byte {
	b := s.bufPool.Get()
	if b == nil {
		return make([]byte, s.mtu())
	}
	return b.([]byte)
}

func (s *Server) freeBuffer(b []byte) {
	s.bufPool.Put(b[:cap(b)])
}

func (s *Server) logger() Logger {
	if s.Logger == nil {
		return (*LevelLogger)(nil)
	}
	return s.Logger
}

// Serve ...
func (s *Server) Serve(iface io.ReadWriteCloser) error {
	log := s.logger()
	h := ipv4.Header{}
	return serveIO(s.getDoneChan(), iface, s, s.getIfaceWriteChan(), func(_ <-chan struct{}, pkt []byte) (ok bool, _ error) {
		if e := parseIPv4Header(&h, pkt); e != nil {
			log.Warn("iface failed to parse ipv4 header:", e)
			return
		}
		if h.Version != 4 {
			log.Tracef("iface drop ip version %d", h.Version)
			return
		}
		log.Tracef("iface recv: %s", &h)
		ss, ok := s.getSessionByIP(h.Dst)
		if !ok {
			log.Debugf("iface drop packet to %s: missing session", h.Dst)
			return
		}
		select {
		case ss.writeChan <- pkt:
			ok = true
			return
		default:
			log.Debugf("iface drop packet to %s: channel full", h.Dst)
			return
		}
	})
}

// Close ...
func (s *Server) Close() {
	done := s.getDoneChan()
	select {
	case <-done:
	default:
		close(done)
	}
}

func (s *Server) getIPv4SessionLocked(cid string) (*Session, bool) {
	ss, ok := s.cidIPv4Session[cid]
	return ss, ok
}

func (s *Server) getIPv6SessionLocked(cid string) (*Session, bool) {
	ss, ok := s.cidIPv6Session[cid]
	return ss, ok
}

func (s *Server) getSessionByIPLocked(ip net.IP) (*Session, bool) {
	ss, ok := s.ipSession[ip.String()]
	return ss, ok
}

func (s *Server) createSessionLocked(ip net.IP, cid string) *Session {
	if s.ipSession == nil {
		s.ipSession = make(map[string]*Session)
		s.cidIPv4Session = make(map[string]*Session)
		s.cidIPv6Session = make(map[string]*Session)
	}

	ss := &Session{
		cid:       cid,
		ip:        ip,
		writeChan: make(chan []byte, defaultServerTunnelWriteChanLen),
	}
	s.ipSession[ss.ip.String()] = ss

	if ip.To4() != nil {
		s.cidIPv4Session[ss.cid] = ss
	} else {
		s.cidIPv6Session[ss.cid] = ss
	}

	return ss
}

func (s *Server) getSessionByIP(ip net.IP) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getSessionByIPLocked(ip)
}

func (s *Server) getOrCreateSession(ip net.IP, cid string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ss, ok := s.getSessionByIPLocked(ip)
	if ok {
		if ss.cid != cid {
			return nil, ErrIPConflict
		}
		return ss, nil
	}

	return s.createSessionLocked(ip, cid), nil
}

// RequestIPv4 ...
func (s *Server) RequestIPv4(cid string) (ip net.IP, ttl time.Duration, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ss, ok := s.getIPv4SessionLocked(cid)
	if ok {
		return ss.ip, ss.ttl, nil
	}

	if s.IPv4Pool == nil {
		err = ErrNoIPv4Config
		return
	}

	ip, ok = s.IPv4Pool.Get()
	if !ok {
		err = ErrIPExhausted
		return
	}

	ss = s.createSessionLocked(ip, cid)
	return ss.ip, ss.ttl, nil
}

// Tunnel ...
func (s *Server) Tunnel(ip net.IP, cid string, rw io.ReadWriteCloser) (err error) {
	ss, err := s.getOrCreateSession(ip, cid)
	if err != nil {
		rw.Close()
		return err
	}

	// flush
	rw.Write(nil)

	log := s.logger()

	log.Info("tunnel opened")
	defer log.Info("tunnel closed")

	ifaceWrite := s.getIfaceWriteChan()
	h := ipv4.Header{}
	return serveIO(s.getDoneChan(), &packetIO{rw}, s, ss.writeChan, func(stop <-chan struct{}, pkt []byte) (ok bool, err error) {
		err = parseIPv4Header(&h, pkt)
		if err != nil {
			log.Warn("tunnel failed to parse ipv4 header:", err)
			return
		}
		log.Tracef("tunnel recv: %s", &h)
		if !h.Src.Equal(ss.ip) {
			log.Warnf("tunnel drop packet from %s: src (%s) mismatched", ss.ip, h.Src)
			return
		}
		select {
		case ifaceWrite <- pkt:
			ok = true
			return
		case <-stop:
			s.freeBuffer(pkt)
			return
		}
	})
}

// Handler ...
func (s *Server) Handler(prefix string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(prefix+"/ip/v4", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		cid := r.Header.Get(headerClientID)
		if cid == "" {
			http.Error(w, "missing "+headerClientID, http.StatusBadRequest)
			return
		}

		ip, ttl, err := s.RequestIPv4(cid)
		if err != nil {
			http.Error(w, err.Error(), getStatusCode(err))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(&struct {
			IP  string `json:"ip"`
			TTL int    `json:"ttl"`
		}{
			IP:  ip.String(),
			TTL: int(ttl / time.Second),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc(prefix+"/tunnel/", func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			http.Error(w, "HTTP/2.0 required", http.StatusUpgradeRequired)
			return
		}

		argIP := strings.TrimPrefix(r.URL.Path, prefix+"/tunnel/")
		if strings.Contains(argIP, "/") {
			http.NotFound(w, r)
			return
		}
		ip := net.ParseIP(argIP)
		if ip == nil {
			http.Error(w, "invalid ip address", http.StatusBadRequest)
			return
		}
		ip = ip.To4()
		if ip == nil {
			http.Error(w, "ipv4 address required", http.StatusBadRequest)
			return
		}

		if r.Method != "POST" {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		cid := r.Header.Get(headerClientID)
		if cid == "" {
			http.Error(w, "missing header: "+headerClientID, http.StatusBadRequest)
			return
		}

		err := s.Tunnel(ip, cid, &httpServerStream{r.Body, w})
		if err != nil {
			http.Error(w, err.Error(), getStatusCode(err))
			return
		}
	})

	return mux
}

type httpServerStream struct {
	io.ReadCloser
	w io.Writer
}

func (s *httpServerStream) Write(b []byte) (int, error) {
	n, err := s.w.Write(b)
	if f, ok := s.w.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}
