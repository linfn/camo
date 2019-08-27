package camo

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const headerClientID = "camo-client-id"

const (
	defaultServerIfaceWriteChanLen  = 256
	defaultServerTunnelWriteChanLen = 256
	defaultSessionTTL               = time.Hour
)

var (
	// ErrNoIPConfig ...
	ErrNoIPConfig = &statusError{http.StatusUnprocessableEntity, "no ip config"}
	// ErrUnableAssignIP ...
	ErrUnableAssignIP = &statusError{http.StatusServiceUnavailable, "unable to assign ip address"}
	// ErrIPConflict ...
	ErrIPConflict = &statusError{http.StatusConflict, "ip conflict"}
	// ErrInvalidIP ...
	ErrInvalidIP = &statusError{http.StatusBadRequest, "invalid ip address"}
)

// Server ...
type Server struct {
	MTU        int
	IPv4Pool   IPPool
	IPv6Pool   IPPool
	SessionTTL time.Duration
	Logger     Logger

	mu             sync.RWMutex
	ipSession      map[string]*session
	cidIPv4Session map[string]*session
	cidIPv6Session map[string]*session

	bufPool        sync.Pool
	ifaceWriteChan chan []byte

	metrics     *Metrics
	metricsOnce sync.Once
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

func (s *Server) mtu() int {
	if s.MTU <= 0 {
		return DefaultMTU
	}
	return s.MTU
}

func (s *Server) getBuffer() (b []byte) {
	v := s.bufPool.Get()
	if v != nil {
		b = v.([]byte)
		s.Metrics().Buffer.FreeBytes.Add(-int64(len(b)))
	} else {
		b = make([]byte, s.mtu())
		s.Metrics().Buffer.TotalBytes.Add(int64(len(b)))
	}
	return b
}

func (s *Server) freeBuffer(b []byte) {
	b = b[:cap(b)]
	s.bufPool.Put(b)
	s.Metrics().Buffer.FreeBytes.Add(int64(len(b)))
}

func (s *Server) logger() Logger {
	if s.Logger == nil {
		return (*LevelLogger)(nil)
	}
	return s.Logger
}

// Metrics ...
func (s *Server) Metrics() *Metrics {
	s.metricsOnce.Do(func() {
		s.metrics = NewMetrics()
	})
	return s.metrics
}

// ServeIface ...
func (s *Server) ServeIface(ctx context.Context, iface io.ReadWriteCloser) error {
	var (
		log     = s.logger()
		metrics = s.Metrics()
		rw      = WithIOMetric(iface, metrics.Iface)
		bufpool = s
	)
	return serveIO(ctx, rw, bufpool, func(_ <-chan struct{}, pkt []byte) (retainBuf bool) {
		ver := GetIPPacketVersion(pkt)

		if log.Level() >= LogLevelTrace {
			if ver == 4 {
				log.Tracef("iface recv: %s", IPv4Header(pkt))
			} else {
				log.Tracef("iface recv: %s", IPv6Header(pkt))
			}
		}

		var dstIP net.IP
		if ver == 4 {
			dstIP = IPv4Header(pkt).Dst()
		} else {
			dstIP = IPv6Header(pkt).Dst()
		}

		ss, ok := s.getSession(dstIP)
		if !ok {
			if !dstIP.IsGlobalUnicast() {
				log.Tracef("iface drop packet: not a global unicast, dstIP %s", dstIP)
			} else {
				log.Tracef("iface drop packet to %s: missing session", dstIP)
			}
			return
		}
		select {
		case ss.writeChan <- pkt:
			retainBuf = true
			metrics.Tunnels.Lags.Add(1)
			return
		default:
			metrics.Tunnels.Drops.Add(1)
			log.Tracef("iface drop packet to %s: channel full", dstIP)
			return
		}
	}, s.getIfaceWriteChan(), nil)
}

func (s *Server) sessionTTL() time.Duration {
	if s.SessionTTL == 0 {
		return defaultSessionTTL
	}
	return s.SessionTTL
}

func ipSessionKey(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 != nil {
		return string(ip4)
	}
	return string(ip)
}

func (s *Server) createSessionLocked(ip net.IP, cid string) *session {
	if s.ipSession == nil {
		s.ipSession = make(map[string]*session)
		s.cidIPv4Session = make(map[string]*session)
		s.cidIPv6Session = make(map[string]*session)
	}

	log := s.logger()

	ss := &session{
		cid:        cid,
		ip:         ip,
		createTime: time.Now(),
		writeChan:  make(chan []byte, defaultServerTunnelWriteChanLen),
	}

	startTimer := func() *time.Timer {
		return time.AfterFunc(s.sessionTTL(), func() {
			if ss.setDone() {
				s.removeSession(ss.ip)
				log.Debugf("session %s expired", ss.ip)
			}
		})
	}
	timer := startTimer()
	ss.onRetained = func() {
		timer.Stop()
	}
	ss.onReleased = func() {
		timer = startTimer()
	}

	s.ipSession[ipSessionKey(ip)] = ss
	if ip.To4() != nil {
		s.cidIPv4Session[cid] = ss
	} else {
		s.cidIPv6Session[cid] = ss
	}

	return ss
}

func (s *Server) getSession(ip net.IP) (*session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ss, ok := s.ipSession[ipSessionKey(ip)]
	return ss, ok
}

func (s *Server) getOrCreateSession(ip net.IP, cid string) (*session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ss, ok := s.ipSession[ipSessionKey(ip)]
	if ok {
		if ss.cid != cid {
			return nil, ErrIPConflict
		}
		return ss, nil
	}

	var ippool IPPool
	if ip.To4() != nil {
		ippool = s.IPv4Pool
	} else {
		ippool = s.IPv6Pool
	}
	if ippool == nil {
		return nil, ErrNoIPConfig
	}
	if !ippool.Use(ip, cid) {
		return nil, ErrInvalidIP
	}

	return s.createSessionLocked(ip, cid), nil
}

func (s *Server) removeSession(ip net.IP) {
	s.mu.Lock()
	if ss, ok := s.ipSession[ipSessionKey(ip)]; ok {
		delete(s.ipSession, ipSessionKey(ip))
		if ip.To4() != nil {
			delete(s.cidIPv4Session, ss.cid)
		} else {
			delete(s.cidIPv6Session, ss.cid)
		}
		s.mu.Unlock()
		metrics := s.Metrics()
	LOOP:
		for {
			select {
			case pkt, ok := <-ss.writeChan:
				if !ok {
					break LOOP
				}
				s.freeBuffer(pkt)
				metrics.Tunnels.Lags.Add(-1)
			default:
				break LOOP
			}
		}
	} else {
		s.mu.Unlock()
	}
}

func (s *Server) assignIPLocked(cid string, cidSession map[string]*session, ipPool IPPool) (ip net.IP, ttl time.Duration, err error) {
	getTTL := func(ttl time.Duration, idle time.Duration) time.Duration {
		d := ttl - idle
		if d < 0 {
			return 0
		}
		return d
	}

	ss, ok := cidSession[cid]
	if ok {
		return ss.ip, getTTL(s.sessionTTL(), ss.idleDuration()), nil
	}

	if ipPool == nil {
		err = ErrNoIPConfig
		return
	}

	ip, ok = ipPool.Get(cid)
	if !ok {
		err = ErrUnableAssignIP
		return
	}

	s.createSessionLocked(ip, cid)
	return ip, s.sessionTTL(), nil
}

// RequestIPv4 ...
func (s *Server) RequestIPv4(cid string) (ip net.IP, ttl time.Duration, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.assignIPLocked(cid, s.cidIPv4Session, s.IPv4Pool)
}

// RequestIPv6 ...
func (s *Server) RequestIPv6(cid string) (ip net.IP, ttl time.Duration, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.assignIPLocked(cid, s.cidIPv6Session, s.IPv6Pool)
}

// OpenTunnel ...
func (s *Server) OpenTunnel(ip net.IP, cid string, rw io.ReadWriteCloser) (func(ctx context.Context) error, error) {
	ss, err := s.getOrCreateSession(ip, cid)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context) error {
		if !ss.retain() {
			rw.Close()
			return errors.New("session expired")
		}
		defer ss.release()

		metrics := s.Metrics()
		metrics.Tunnels.Streams.Add(1)
		defer metrics.Tunnels.Streams.Add(-1)

		rw = WithIOMetric(&packetIO{rw}, metrics.Tunnels.IOMetric)
		postWrite := func(<-chan struct{}, error) { metrics.Tunnels.Lags.Add(-1) }

		var (
			log        = s.logger()
			ifaceWrite = s.getIfaceWriteChan()
			bufpool    = s
		)
		err := serveIO(ctx, rw, bufpool, func(done <-chan struct{}, pkt []byte) (retainBuf bool) {
			ver := GetIPPacketVersion(pkt)

			if log.Level() >= LogLevelTrace {
				if ver == 4 {
					log.Tracef("tunnel recv: %s", IPv4Header(pkt))
				} else {
					log.Tracef("tunnel recv: %s", IPv6Header(pkt))
				}
			}

			var (
				srcIP net.IP
				dstIP net.IP
			)
			if ver == 4 {
				h := IPv4Header(pkt)
				srcIP = h.Src()
				dstIP = h.Dst()
			} else {
				h := IPv6Header(pkt)
				srcIP = h.Src()
				dstIP = h.Dst()
			}

			if !srcIP.Equal(ss.ip) {
				log.Warnf("tunnel drop packet from %s: src %s mismatched", ss.ip, srcIP)
				return
			}

			if !dstIP.IsGlobalUnicast() {
				log.Tracef("tunnel drop packet from %s: not a global unicast, dst %s", ss.ip, dstIP)
				return
			}

			select {
			case ifaceWrite <- pkt:
				retainBuf = true
				return
			case <-done:
				return
			}
		}, ss.writeChan, postWrite)
		if err == io.EOF {
			return nil
		}
		return err
	}, nil
}

// Handler ...
func (s *Server) Handler(ctx context.Context, prefix string) http.Handler {
	mux := http.NewServeMux()

	ipHandler := func(version int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
				return
			}

			cid := r.Header.Get(headerClientID)
			if cid == "" {
				http.Error(w, "missing "+headerClientID, http.StatusBadRequest)
				return
			}

			var (
				ip  net.IP
				ttl time.Duration
				err error
			)
			if version == 4 {
				ip, ttl, err = s.RequestIPv4(cid)
			} else {
				ip, ttl, err = s.RequestIPv6(cid)
			}
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
		}
	}
	mux.HandleFunc(prefix+"/ip/v4", ipHandler(4))
	mux.HandleFunc(prefix+"/ip/v6", ipHandler(6))

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

		if r.Method != "POST" {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		cid := r.Header.Get(headerClientID)
		if cid == "" {
			http.Error(w, "missing header: "+headerClientID, http.StatusBadRequest)
			return
		}

		tunnel, err := s.OpenTunnel(ip, cid, &httpServerStream{r.Body, w})
		if err != nil {
			http.Error(w, err.Error(), getStatusCode(err))
			return
		}

		// flush the header frame
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		log := s.logger()
		log.Infof("tunnel %s opened, cid: %s, remote: %s", ip, cid, r.RemoteAddr)

		err = tunnel(ctx)
		if err != nil {
			log.Infof("tunnel %s closed. %v", ip, err)
		} else {
			log.Infof("tunnel %s closed", ip)
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
