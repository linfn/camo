package camo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/linfn/camo/internal/util"
)

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
	Noise      int

	mu             sync.RWMutex
	ipSession      map[string]*session
	cidIPv4Session map[string]*session
	cidIPv6Session map[string]*session

	bufPool        sync.Pool
	ifaceWriteChan chan *packetBuffer

	metrics     *Metrics
	metricsOnce sync.Once
}

func (s *Server) getIfaceWriteChan() chan *packetBuffer {
	s.mu.RLock()
	if s.ifaceWriteChan != nil {
		s.mu.RUnlock()
		return s.ifaceWriteChan
	}
	s.mu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ifaceWriteChan == nil {
		s.ifaceWriteChan = make(chan *packetBuffer, defaultServerIfaceWriteChanLen)
	}
	return s.ifaceWriteChan
}

func (s *Server) mtu() int {
	if s.MTU <= 0 {
		return DefaultMTU
	}
	return s.MTU
}

func (s *Server) getBuffer() (p *packetBuffer) {
	v := s.bufPool.Get()
	if v != nil {
		p = v.(*packetBuffer)
		s.Metrics().Buffer.FreeBytes.Add(-int64(cap(p.Data)))
	} else {
		p = &packetBuffer{Data: make([]byte, s.mtu())}
		s.Metrics().Buffer.TotalBytes.Add(int64(cap(p.Data)))
	}
	return p
}

func (s *Server) freeBuffer(p *packetBuffer) {
	p.Reset()
	s.bufPool.Put(p)
	s.Metrics().Buffer.FreeBytes.Add(int64(cap(p.Data)))
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
	return serveIO(ctx, rw, bufpool, func(_ <-chan struct{}, p *packetBuffer) (retainBuf bool) {
		ver := GetIPPacketVersion(p.Data)

		if log.Level() >= LogLevelTrace {
			if ver == 4 {
				log.Tracef("iface recv: %s", IPv4Header(p.Data))
			} else {
				log.Tracef("iface recv: %s", IPv6Header(p.Data))
			}
		}

		var dstIP net.IP
		if ver == 4 {
			dstIP = IPv4Header(p.Data).Dst()
		} else {
			dstIP = IPv6Header(p.Data).Dst()
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
		case ss.writeChan <- p:
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

func (s *Server) createSessionLocked(ip net.IP, mask net.IPMask, gw net.IP, cid string) *session {
	if s.ipSession == nil {
		s.ipSession = make(map[string]*session)
		s.cidIPv4Session = make(map[string]*session)
		s.cidIPv6Session = make(map[string]*session)
	}

	log := s.logger()

	ss := &session{
		cid:        cid,
		ip:         ip,
		mask:       mask,
		gw:         gw,
		createTime: time.Now(),
		writeChan:  make(chan *packetBuffer, defaultServerTunnelWriteChanLen),
	}

	startTimer := func() *time.Timer {
		return time.AfterFunc(s.sessionTTL(), func() {
			if ss.trySetDone() {
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
	ipmask, ok := ippool.Use(ip, cid)
	if !ok {
		return nil, ErrInvalidIP
	}

	return s.createSessionLocked(ip, ipmask, ippool.Gateway(), cid), nil
}

var testHookSessionRemoved func(ss *session)

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
		if testHookSessionRemoved != nil {
			testHookSessionRemoved(ss)
		}
	} else {
		s.mu.Unlock()
	}
}

// IPResult is result returned by RequestIPv4/RequestIPv6
type IPResult struct {
	IP      net.IP
	Mask    net.IPMask
	TTL     time.Duration
	Gateway net.IP
}

func (r *IPResult) String() string {
	return fmt.Sprintf("ip=%s ttl=%d gw=%s", util.ToCIDR(r.IP, r.Mask), r.TTL, r.Gateway)
}

func (s *Server) assignIPLocked(cid string, cidSession map[string]*session, ipPool IPPool) (*IPResult, error) {
	getTTL := func(ttl time.Duration, idle time.Duration) time.Duration {
		d := ttl - idle
		if d < 0 {
			return 0
		}
		return d
	}

	ss, ok := cidSession[cid]
	if ok {
		return &IPResult{ss.ip, ss.mask, getTTL(s.sessionTTL(), ss.idleDuration()), ss.gw}, nil
	}

	if ipPool == nil {
		return nil, ErrNoIPConfig
	}

	ip, mask, ok := ipPool.Get(cid)
	if !ok {
		return nil, ErrUnableAssignIP
	}
	gw := ipPool.Gateway()

	s.createSessionLocked(ip, mask, gw, cid)
	return &IPResult{ip, mask, s.sessionTTL(), gw}, nil
}

// RequestIPv4 ...
func (s *Server) RequestIPv4(cid string) (*IPResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.assignIPLocked(cid, s.cidIPv4Session, s.IPv4Pool)
}

// RequestIPv6 ...
func (s *Server) RequestIPv6(cid string) (*IPResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.assignIPLocked(cid, s.cidIPv6Session, s.IPv6Pool)
}

// CreateTunnel ...
func (s *Server) CreateTunnel(ip net.IP, cid string, rw io.ReadWriteCloser) (func(ctx context.Context) error, error) {
	ss, err := s.getOrCreateSession(ip, cid)
	if err != nil {
		return nil, err
	}

	release, robbed, ok := ss.retain()
	if !ok {
		return nil, errors.New("session expired")
	}

	return func(baseCtx context.Context) (err error) {
		defer release()

		ctx, cancel := context.WithCancel(baseCtx)
		defer cancel()

		var errOnce sync.Once
		setErr := func(e error) {
			errOnce.Do(func() {
				err = e
			})
		}

		go func() {
			select {
			case <-robbed:
				setErr(errors.New("session is robbed"))
				cancel()
			case <-ctx.Done():
			}
		}()

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
		setErr(serveIO(ctx, rw, bufpool, func(done <-chan struct{}, p *packetBuffer) (retainBuf bool) {
			ver := GetIPPacketVersion(p.Data)

			if log.Level() >= LogLevelTrace {
				if ver == 4 {
					log.Tracef("tunnel recv: %s", IPv4Header(p.Data))
				} else {
					log.Tracef("tunnel recv: %s", IPv6Header(p.Data))
				}
			}

			var (
				srcIP net.IP
				dstIP net.IP
			)
			if ver == 4 {
				h := IPv4Header(p.Data)
				srcIP = h.Src()
				dstIP = h.Dst()
			} else {
				h := IPv6Header(p.Data)
				srcIP = h.Src()
				dstIP = h.Dst()
			}

			if !srcIP.Equal(ss.ip) {
				log.Tracef("tunnel drop packet from %s: src %s mismatched", ss.ip, srcIP)
				return
			}

			if !dstIP.IsGlobalUnicast() {
				log.Tracef("tunnel drop packet from %s: not a global unicast, dst %s", ss.ip, dstIP)
				return
			}

			select {
			case ifaceWrite <- p:
				retainBuf = true
				return
			case <-done:
				return
			}
		}, ss.writeChan, postWrite))
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
				res *IPResult
				err error
			)
			if version == 4 {
				res, err = s.RequestIPv4(cid)
			} else {
				res, err = s.RequestIPv6(cid)
			}
			if err != nil {
				http.Error(w, err.Error(), getStatusCode(err))
				return
			}
			notation, _ := res.Mask.Size()

			w.Header().Set("Content-Type", "application/json")
			err = json.NewEncoder(w).Encode(&struct {
				IP       string `json:"ip"`
				Notation int    `json:"notation"`
				TTL      int    `json:"ttl"`
				Gateway  string `json:"gateway"`
			}{
				IP:       res.IP.String(),
				Notation: notation,
				TTL:      int(res.TTL / time.Second),
				Gateway:  res.Gateway.String(),
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

		tunnel, err := s.CreateTunnel(ip, cid, &httpServerStream{r.Body, w})
		if err != nil {
			http.Error(w, err.Error(), getStatusCode(err))
			return
		}

		// flush the header frame
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		log := s.logger()
		log.Infof("tunnel %s created, cid: %s, remote: %s", ip, cid, r.RemoteAddr)

		err = tunnel(ctx)
		if err != nil {
			log.Infof("tunnel %s closed. %v", ip, err)
		} else {
			log.Infof("tunnel %s closed", ip)
		}
	})

	withNoise := func(noise int, handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(headerNoise, getNoisePadding(noise, r.Method+r.URL.Path))
			handler.ServeHTTP(w, r)
		})
	}

	if s.Noise != 0 {
		return withNoise(s.Noise, mux)
	}

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
