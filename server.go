package camo

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

const (
	defaultServerIfaceWriteChanLen  = 256
	defaultServerTunnelWriteChanLen = 256
)

var (
	// ErrNoIPv4Config ...
	ErrNoIPv4Config = Error(http.StatusBadRequest, "server no ipv4 config")
	// ErrIPExhausted ...
	ErrIPExhausted = Error(http.StatusServiceUnavailable, "ip exhausted")
	// ErrSessionNotFound ...
	ErrSessionNotFound = Error(http.StatusBadRequest, "session not found")
)

// Server ...
type Server struct {
	MTU      int
	IPv4Pool *IPPool

	mu         sync.RWMutex
	cidSession map[string]*Session
	ipSession  map[string]*Session

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

// Serve ...
func (s *Server) Serve(iface io.ReadWriteCloser) error {
	var h ipv4.Header
	return serveIO(s.getDoneChan(), iface, s, s.getIfaceWriteChan(), func(_ <-chan struct{}, pkt []byte) (ok bool, _ error) {
		if e := parseIPv4Header(&h, pkt); e != nil {
			log.Printf("(debug) iface failed to parse ipv4 header %v", e)
			return
		}
		if h.Version != 4 {
			//log.Printf("(debug) iface drop ip version %d", h.Version)
			return
		}
		log.Printf("(debug) iface recv: %s", &h)
		ss, ok := s.findSessionByIP(h.Dst)
		if !ok {
			log.Printf("(debug) iface drop packet to %s: missing session", h.Dst)
			return
		}
		select {
		case ss.writeChan <- pkt:
			ok = true
			return
		default:
			log.Printf("(debug) iface drop packet to %s: channel full", h.Dst)
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

// RequestIPv4 ...
func (s *Server) RequestIPv4(cid string, reqIP net.IP) (ip net.IP, ttl time.Duration, err error) {
	if cid == "" {
		err = Error(http.StatusBadRequest, "empty cid")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cidSession == nil {
		s.cidSession = make(map[string]*Session)
		s.ipSession = make(map[string]*Session)
	}

	ss, ok := s.cidSession[cid]
	if ok {
		return ss.ipv4, 0, nil
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

	ss = &Session{
		cid:       cid,
		ipv4:      ip,
		writeChan: make(chan []byte, defaultServerTunnelWriteChanLen),
	}
	s.cidSession[ss.cid] = ss
	s.ipSession[ss.ipv4.String()] = ss

	return ip, 0, nil
}

// Tunnel ...
func (s *Server) Tunnel(cid string, rw io.ReadWriteCloser) (err error) {
	ss, ok := s.findSessionByCID(cid)
	if !ok {
		rw.Close()
		return ErrSessionNotFound
	}

	// flush
	rw.Write(nil)

	log.Println("tunnel opened")
	defer log.Println("tunnel closed")

	ifaceWrite := s.getIfaceWriteChan()
	h := ipv4.Header{}
	return serveIO(s.getDoneChan(), &packetIO{rw}, s, ss.writeChan, func(stop <-chan struct{}, pkt []byte) (ok bool, err error) {
		err = parseIPv4Header(&h, pkt)
		if err != nil {
			log.Printf("(debug) tunnel failed to parse ipv4 header %v", err)
			return
		}
		log.Printf("(debug) tunnel recv: %s", &h)
		if !h.Src.Equal(ss.ipv4) {
			log.Printf("(debug) tunnel drop packet from %s: src (%s) mismatched", ss.ipv4, h.Src)
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
	mux.Handle(prefix+"/ip/v4", http.RedirectHandler(prefix+"/ip/v4/", http.StatusPermanentRedirect))
	mux.HandleFunc(prefix+"/ip/v4/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, prefix+"/ip/v4/")
		if strings.Contains(path, "/") {
			http.NotFound(w, r)
			return
		}
		if r.Method != "POST" {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		var reqIP net.IP
		if ip := path; len(ip) > 0 {
			reqIP = net.ParseIP(ip)
			if reqIP == nil {
				http.Error(w, "Invalid ip", http.StatusBadRequest)
				return
			}
		}

		var reqBody struct {
			CID string `json:"cid"`
		}
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} else if reqBody.CID == "" {
			http.Error(w, "Empty cid", http.StatusBadRequest)
			return
		}

		ip, ttl, err := s.RequestIPv4(reqBody.CID, reqIP)
		if err != nil {
			http.Error(w, err.Error(), GetStatusCode(err))
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
		path := strings.TrimPrefix(r.URL.Path, prefix+"/tunnel/")
		if strings.Contains(path, "/") {
			http.NotFound(w, r)
			return
		}
		if r.Method != "POST" {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		cid := path
		if cid == "" {
			http.Error(w, "Empty cid", http.StatusBadRequest)
			return
		}

		err := s.Tunnel(cid, &httpServerStream{r.Body, w})
		if err != nil {
			http.Error(w, err.Error(), GetStatusCode(err))
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
