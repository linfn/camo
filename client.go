package camo

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/ipv4"
)

const (
	defaultClientIfaceWriteChanLen  = 256
	defaultClientTunnelWriteChanLen = 256
)

// Client ...
type Client struct {
	CID         string
	Host        string
	ResolveAddr string
	Auth        func(r *http.Request)
	MTU         int
	SetupTunnel func(localIP net.IP, remoteIP net.IP) (reset func(), err error)
	Logger      Logger
	UseH2C      bool

	mu              sync.Mutex
	bufPool         sync.Pool
	ifaceWriteChan  chan []byte
	tunnelWriteChan chan []byte
	doneChan        chan struct{}

	metrics     *Metrics
	metricsOnce sync.Once
}

func (c *Client) getDoneChan() chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.doneChan == nil {
		c.doneChan = make(chan struct{})
	}
	return c.doneChan
}

func (c *Client) getIfaceWriteChan() chan []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ifaceWriteChan == nil {
		c.ifaceWriteChan = make(chan []byte, defaultClientIfaceWriteChanLen)
	}
	return c.ifaceWriteChan
}

func (c *Client) getTunnelWriteChan() chan []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tunnelWriteChan == nil {
		c.tunnelWriteChan = make(chan []byte, defaultClientTunnelWriteChanLen)
	}
	return c.tunnelWriteChan
}

func (c *Client) mtu() int {
	if c.MTU <= 0 {
		return DefaultMTU
	}
	return c.MTU
}

func (c *Client) getBuffer() []byte {
	b := c.bufPool.Get()
	if b != nil {
		return b.([]byte)
	}
	buf := make([]byte, c.mtu())
	c.Metrics().BufferSize.Add(int64(len(buf)))
	return buf
}

func (c *Client) freeBuffer(b []byte) {
	c.bufPool.Put(b[:cap(b)])
}

func (c *Client) logger() Logger {
	if c.Logger == nil {
		return (*LevelLogger)(nil)
	}
	return c.Logger
}

// Metrics ...
func (c *Client) Metrics() *Metrics {
	c.metricsOnce.Do(func() {
		c.metrics = NewMetrics()
	})
	return c.metrics
}

func (c *Client) resolveAddr() (string, error) {
	var addr string
	if c.ResolveAddr != "" {
		addr = c.ResolveAddr
	} else {
		addr = c.Host
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}
	a, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return "", err
	}
	return a.String(), nil
}

func (c *Client) h2Transport(resolvedAddr string) http.RoundTripper {
	return &http2.Transport{
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			if resolvedAddr != "" {
				addr = resolvedAddr
			}
			if c.UseH2C {
				return net.Dial(network, addr)
			}
			// http2: Transport.dialTLSDefault
			cn, err := tls.Dial(network, addr, cfg)
			if err != nil {
				return nil, err
			}
			if err := cn.Handshake(); err != nil {
				return nil, err
			}
			if !cfg.InsecureSkipVerify {
				if err := cn.VerifyHostname(cfg.ServerName); err != nil {
					return nil, err
				}
			}
			state := cn.ConnectionState()
			if p := state.NegotiatedProtocol; p != http2.NextProtoTLS {
				return nil, fmt.Errorf("http2: unexpected ALPN protocol %q; want %q", p, http2.NextProtoTLS)
			}
			if !state.NegotiatedProtocolIsMutual {
				return nil, errors.New("http2: could not negotiate protocol mutually")
			}
			return cn, nil
		},
	}
}

func (c *Client) serveIface(stop <-chan struct{}, iface io.ReadWriteCloser) error {
	var (
		log             = c.logger()
		metrics         = c.Metrics()
		rw              = WithIOMetric(iface, metrics.Iface)
		tunnelWriteChan = c.getTunnelWriteChan()
		h               ipv4.Header
	)
	return serveIO(stop, rw, c, func(stop <-chan struct{}, pkt []byte) (ok bool) {
		if e := parseIPv4Header(&h, pkt); e != nil {
			log.Warn("iface failed to parse ipv4 header:", e)
			return
		}
		if h.Version != 4 {
			log.Tracef("iface drop ip version %d", h.Version)
			return
		}
		log.Tracef("iface recv: %s", &h)
		select {
		case tunnelWriteChan <- pkt:
			ok = true
			metrics.Tunnels.Lags.Add(1)
			return
		case <-stop:
			return
		}
	}, c.getIfaceWriteChan(), nil)
}

// Run ...
func (c *Client) Run(iface io.ReadWriteCloser) (err error) {
	defer iface.Close()

	if c.CID == "" {
		return errors.New("empty cid")
	}

	log := c.logger()

	resolvedAddr, err := c.resolveAddr()
	if err != nil {
		return fmt.Errorf("failed to resolve host: %v", err)
	}
	srvip, _, _ := net.SplitHostPort(resolvedAddr)
	log.Infof("server address is %s", resolvedAddr)

	hc := &http.Client{}
	hc.Transport = c.h2Transport(resolvedAddr)

	ip, ttl, err := c.reqIPv4(context.TODO(), hc)
	if err != nil {
		return err
	}

	log.Infof("client get ip (%s) ttl (%d)", ip, ttl)

	tunnel, err := c.openTunnel(hc, ip)
	if err != nil {
		return err
	}

	log.Infof("tunnel %s opened", ip)
	defer log.Infof("tunnel %s closed", ip)

	if c.SetupTunnel != nil {
		reset, err := c.SetupTunnel(ip, net.ParseIP(srvip))
		if err != nil {
			done := make(chan struct{})
			close(done)
			tunnel(done)
			return fmt.Errorf("setup route error: %v", err)
		}
		defer reset()
	}

	done := make(chan struct{})
	exit := func(e error) {
		select {
		case <-done:
		default:
			close(done)
			err = e
		}
	}

	go func() {
		clientDone := c.getDoneChan()
		select {
		case <-clientDone:
			exit(nil)
		case <-done:
		}
	}()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := tunnel(done)
		if err != nil {
			err = fmt.Errorf("tunnel exited: %v", err)
		}
		exit(err)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := c.serveIface(done, iface)
		if err != nil {
			err = fmt.Errorf("serve iface exited: %v", err)
		}
		exit(err)
	}()

	wg.Wait()
	return
}

func (c *Client) url(path string) *url.URL {
	return &url.URL{
		Scheme: "https",
		Host:   c.Host,
		Path:   path,
	}
}

func (c *Client) setAuth(r *http.Request) {
	if c.Auth != nil {
		c.Auth(r)
	}
}

func (c *Client) reqIPv4(ctx context.Context, hc *http.Client) (ip net.IP, ttl time.Duration, err error) {
	req := &http.Request{
		Method: "POST",
		URL:    c.url("/ip/v4"),
		Header: http.Header{
			headerClientID: []string{c.CID},
		},
	}
	c.setAuth(req)
	res, err := hc.Do(req.WithContext(ctx))
	if err != nil {
		if err == context.Canceled || err == context.DeadlineExceeded {
			return
		}
		err = fmt.Errorf("failed to get ip, error: %v", err)
		return
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("failed to get ip, status: %s", res.Status)
		return
	}

	var result struct {
		IP  string `json:"ip"`
		TTL int    `json:"ttl"`
	}
	err = json.NewDecoder(res.Body).Decode(&result)
	if err != nil {
		err = fmt.Errorf("failed to decode ip result, error: %s", err)
		return
	}
	ip = net.ParseIP(result.IP)
	if ip == nil {
		err = fmt.Errorf("failed to decode ip (%s)", result.IP)
		return
	}

	return ip, time.Duration(result.TTL) * time.Second, nil
}

type httpClientStream struct {
	io.ReadCloser
	io.WriteCloser
}

func (s *httpClientStream) Close() error {
	err1 := s.ReadCloser.Close()
	err2 := s.WriteCloser.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *Client) openTunnel(hc *http.Client, ip net.IP) (func(stop <-chan struct{}) error, error) {
	r, w := io.Pipe()
	req := &http.Request{
		Method: "POST",
		URL:    c.url("/tunnel/" + ip.String()),
		Header: http.Header{
			headerClientID: []string{c.CID},
		},
		Body: ioutil.NopCloser(r),
	}
	c.setAuth(req)
	res, err := hc.Do(req.WithContext(context.TODO()))
	if err != nil {
		w.Close()
		return nil, fmt.Errorf("failed to open tunnel, error: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		w.Close()
		res.Body.Close()
		return nil, fmt.Errorf("failed to open tunnel, status: %s", res.Status)
	}

	return func(stop <-chan struct{}) error {
		var (
			log            = c.logger()
			metrics        = c.Metrics()
			rw             = WithIOMetric(&packetIO{&httpClientStream{res.Body, w}}, metrics.Tunnels.IOMetric)
			ifaceWriteChan = c.getIfaceWriteChan()
			postWrite      = func(<-chan struct{}, error) { metrics.Tunnels.Lags.Add(-1) }
			h              ipv4.Header
		)
		return serveIO(stop, rw, c, func(stop <-chan struct{}, pkt []byte) (ok bool) {
			if e := parseIPv4Header(&h, pkt); e != nil {
				log.Warn("tunnel failed to parse ipv4 header:", e)
				return
			}
			log.Tracef("tunnel recv: %s", &h)
			select {
			case ifaceWriteChan <- pkt:
				ok = true
				return
			case <-stop:
				return
			}
		}, c.getTunnelWriteChan(), postWrite)
	}, nil
}

// Close ...
func (c *Client) Close() {
	done := c.getDoneChan()
	select {
	case <-done:
	default:
		close(done)
	}
}
