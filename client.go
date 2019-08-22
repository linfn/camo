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
	MTU    int
	CID    string
	Host   string
	Addr   *net.TCPAddr
	Auth   func(r *http.Request)
	Logger Logger
	UseH2C bool

	mu              sync.Mutex
	bufPool         sync.Pool
	ifaceWriteChan  chan []byte
	tunnelWriteChan chan []byte

	cacheAddr *net.TCPAddr
	hc        *http.Client

	metrics     *Metrics
	metricsOnce sync.Once
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

func (c *Client) getBuffer() (b []byte) {
	v := c.bufPool.Get()
	if v != nil {
		b = v.([]byte)
		c.Metrics().Buffer.FreeBytes.Add(-int64(len(b)))
	} else {
		b = make([]byte, c.mtu())
		c.Metrics().Buffer.TotalBytes.Add(int64(len(b)))
	}
	return b
}

func (c *Client) freeBuffer(b []byte) {
	b = b[:cap(b)]
	c.bufPool.Put(b)
	c.Metrics().Buffer.FreeBytes.Add(int64(len(b)))
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

// ServeIface ...
func (c *Client) ServeIface(ctx context.Context, iface io.ReadWriteCloser) error {
	var (
		log             = c.logger()
		metrics         = c.Metrics()
		rw              = WithIOMetric(iface, metrics.Iface)
		tunnelWriteChan = c.getTunnelWriteChan()
		bufpool         = c
		h               ipv4.Header
	)
	return serveIO(ctx, rw, bufpool, func(done <-chan struct{}, pkt []byte) (retainBuf bool) {
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
			retainBuf = true
			metrics.Tunnels.Lags.Add(1)
			return
		case <-done:
			return
		}
	}, c.getIfaceWriteChan(), nil)
}

func (c *Client) serveTunnel(ctx context.Context, rw io.ReadWriteCloser) error {
	metrics := c.Metrics().Tunnels

	metrics.Streams.Add(1)
	defer metrics.Streams.Add(-1)

	rw = WithIOMetric(&packetIO{rw}, metrics.IOMetric)

	var (
		log            = c.logger()
		ifaceWriteChan = c.getIfaceWriteChan()
		postWrite      = func(<-chan struct{}, error) { metrics.Lags.Add(-1) }
		bufpool        = c
		h              ipv4.Header
	)
	return serveIO(ctx, rw, bufpool, func(done <-chan struct{}, pkt []byte) (retainBuf bool) {
		if e := parseIPv4Header(&h, pkt); e != nil {
			log.Warn("tunnel failed to parse ipv4 header:", e)
			return
		}
		log.Tracef("tunnel recv: %s", &h)
		select {
		case ifaceWriteChan <- pkt:
			retainBuf = true
			return
		case <-done:
			return
		}
	}, c.getTunnelWriteChan(), postWrite)
}

// ResolveAddr ...
func (c *Client) ResolveAddr() (*net.TCPAddr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.resolveAddrLocked()
}

func (c *Client) resolveAddrLocked() (*net.TCPAddr, error) {
	if c.cacheAddr != nil {
		return c.cacheAddr, nil
	}

	if c.Addr != nil {
		c.cacheAddr = c.Addr
	} else {
		addr := c.Host
		if _, _, err := net.SplitHostPort(c.Host); err != nil {
			addr = net.JoinHostPort(addr, "443")
		}
		tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			return nil, err
		}
		c.cacheAddr = tcpAddr
	}
	c.logger().Infof("server address is %s", c.cacheAddr)
	return c.cacheAddr, nil
}

// FlushAddr ...
func (c *Client) FlushAddr() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cacheAddr = nil
	if c.hc != nil {
		c.hc.CloseIdleConnections()
		c.hc = nil
	}
}

func (c *Client) h2Transport(resolveAddr *net.TCPAddr) http.RoundTripper {
	return &http2.Transport{
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			if resolveAddr != nil {
				addr = resolveAddr.String()
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

func (c *Client) httpClient() (*http.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hc != nil {
		return c.hc, nil
	}
	srvAddr, err := c.resolveAddrLocked()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve host: %v", err)
	}
	c.hc = &http.Client{
		Transport: c.h2Transport(srvAddr),
	}
	return c.hc, nil
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

// ClientAPIError ...
type ClientAPIError struct {
	Err  error
	temp bool
}

func (e *ClientAPIError) Error() string {
	return e.Err.Error()
}

// Temporary ...
func (e *ClientAPIError) Temporary() bool {
	return e.temp
}

func (c *Client) doReq(req *http.Request) (*http.Response, error) {
	c.setAuth(req)

	hc, err := c.httpClient()
	if err != nil {
		return nil, &ClientAPIError{Err: err, temp: true}
	}
	res, err := hc.Do(req)
	if err != nil {
		if e, ok := err.(*url.Error); ok && e.Err == context.Canceled {
			err = &ClientAPIError{Err: context.Canceled, temp: false}
		} else {
			err = &ClientAPIError{Err: err, temp: true}
		}
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		var msg string
		b, err := ioutil.ReadAll(res.Body)
		msg = string(b)
		if err != nil {
			msg += "..+" + err.Error()
		}
		res.Body.Close()
		return res, &ClientAPIError{
			Err:  &statusError{res.StatusCode, string(msg)},
			temp: isStatusRetryable(res.StatusCode),
		}
	}

	return res, nil
}

// RequestIPv4 ...
func (c *Client) RequestIPv4(ctx context.Context) (ip net.IP, ttl time.Duration, err error) {
	req := &http.Request{
		Method: "POST",
		URL:    c.url("/ip/v4"),
		Header: http.Header{
			headerClientID: []string{c.CID},
		},
	}
	res, err := c.doReq(req.WithContext(ctx))
	if err != nil {
		return
	}
	defer res.Body.Close()

	var result struct {
		IP  string `json:"ip"`
		TTL int    `json:"ttl"`
	}
	err = json.NewDecoder(res.Body).Decode(&result)
	if err != nil {
		var temp bool
		if _, ok := err.(*json.SyntaxError); !ok {
			temp = true
		}
		err = &ClientAPIError{Err: fmt.Errorf("failed to decode ip result, error: %s", err), temp: temp}
		return
	}
	ip = net.ParseIP(result.IP)
	if ip == nil {
		err = &ClientAPIError{Err: fmt.Errorf("failed to decode ip (%s)", result.IP), temp: false}
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

// OpenTunnel ...
func (c *Client) OpenTunnel(ctx context.Context, ip net.IP) (func(context.Context) error, error) {
	r, w := io.Pipe()
	req := &http.Request{
		Method: "POST",
		URL:    c.url("/tunnel/" + ip.String()),
		Header: http.Header{
			headerClientID: []string{c.CID},
		},
		Body: ioutil.NopCloser(r),
	}
	// TODO 这里不能直接使用 ctx 作为 req 的 Context, 我们需要保持 req.Body 和 res.Body 组成的双向流
	res, err := c.doReq(req.WithContext(context.TODO()))
	if err != nil {
		w.Close()
		return nil, err
	}
	return func(ctx context.Context) error {
		return c.serveTunnel(ctx, &httpClientStream{res.Body, w})
	}, nil
}

// RunClient ...
func RunClient(ctx context.Context, c *Client, iface io.ReadWriteCloser, setupTun func(localIP net.IP) (reset func(), err error)) (err error) {
	defer iface.Close()

	log := c.logger()

	openTunnel := func(ctx context.Context) (func(context.Context) error, error) {
		var err error

		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)

		ip, ttl, err := c.RequestIPv4(ctx)
		if err != nil {
			cancel()
			return nil, err
		}

		log.Infof("client get ip (%s) ttl (%d)", ip, ttl)

		tunnel, err := c.OpenTunnel(ctx, ip)
		if err != nil {
			cancel()
			return nil, err
		}

		cancel()

		reset, err := setupTun(ip)
		if err != nil {
			tunnel(ctx) // use a canceled ctx to terminate the tunnel
			return nil, fmt.Errorf("setup tunnel error: %v", err)
		}

		return func(ctx context.Context) error {
			defer reset()
			return tunnel(ctx)
		}, nil
	}

	ctx, cancel := context.WithCancel(ctx)

	var exitOnce sync.Once
	exit := func(e error) {
		exitOnce.Do(func() {
			err = e
			cancel()
		})
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		e := c.ServeIface(ctx, iface)
		if e == context.Canceled {
			exit(context.Canceled)
		} else {
			exit(fmt.Errorf("serve iface exited: %v", e))
		}
	}()

	for {
		tunnel, e := openTunnel(ctx)
		if e != nil {
			if ae, ok := e.(*ClientAPIError); ok {
				if ae.Temporary() {
					log.Errorf("failed to open tunnel: %v", e)
					goto RETRY
				}
				if ae.Err == context.Canceled {
					e = context.Canceled
				}
			}
			exit(e)
			break
		}

		log.Info("tunnel opened")

		e = tunnel(ctx)
		if e == context.Canceled {
			log.Info("tunnel closed")
			exit(context.Canceled)
			break
		}
		log.Errorf("tunnel closed: %v", e)

	RETRY:
		// TODO exponential backoff
		time.Sleep(1 * time.Second)
		c.FlushAddr()
	}

	wg.Wait()
	return err
}
