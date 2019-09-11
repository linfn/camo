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
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const (
	defaultClientIfaceWriteChanLen  = 256
	defaultClientTunnelWriteChanLen = 256
)

// Client ...
type Client struct {
	MTU       int
	CID       string
	Host      string
	Dial      func(network, addr string) (net.Conn, error)
	TLSConfig *tls.Config
	URLPrefix string
	Auth      func(r *http.Request)
	Logger    Logger
	UseH2C    bool
	Noise     int

	mu               sync.Mutex
	bufPool          sync.Pool
	ifaceWriteChan   chan []byte
	tunnel4WriteChan chan []byte
	tunnel6WriteChan chan []byte

	hc *http.Client

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

func (c *Client) getTunnel4WriteChan() chan []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tunnel4WriteChan == nil {
		c.tunnel4WriteChan = make(chan []byte, defaultClientTunnelWriteChanLen)
	}
	return c.tunnel4WriteChan
}

func (c *Client) getTunnel6WriteChan() chan []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tunnel6WriteChan == nil {
		c.tunnel6WriteChan = make(chan []byte, defaultClientTunnelWriteChanLen)
	}
	return c.tunnel6WriteChan
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
		log     = c.logger()
		metrics = c.Metrics()
		rw      = WithIOMetric(iface, metrics.Iface)
		tunnel4 = c.getTunnel4WriteChan()
		tunnel6 = c.getTunnel6WriteChan()
		bufpool = c
	)
	return serveIO(ctx, rw, bufpool, func(done <-chan struct{}, pkt []byte) (retainBuf bool) {
		ver := GetIPPacketVersion(pkt)

		if log.Level() >= LogLevelTrace {
			if ver == 4 {
				log.Tracef("iface recv: %s", IPv4Header(pkt))
			} else {
				log.Tracef("iface recv: %s", IPv6Header(pkt))
			}
		}

		var (
			dstIP  net.IP
			tunnel chan []byte
		)
		if ver == 4 {
			dstIP = IPv4Header(pkt).Dst()
			tunnel = tunnel4
		} else {
			dstIP = IPv6Header(pkt).Dst()
			tunnel = tunnel6
		}

		if !dstIP.IsGlobalUnicast() {
			log.Tracef("iface drop packet: not a global unicast, dstIP %s", dstIP)
			return
		}

		select {
		case tunnel <- pkt:
			retainBuf = true
			metrics.Tunnels.Lags.Add(1)
			return
		case <-done:
			return
		}
	}, c.getIfaceWriteChan(), nil)
}

func (c *Client) serveTunnel(ctx context.Context, rw io.ReadWriteCloser, localIP net.IP) error {
	metrics := c.Metrics().Tunnels

	metrics.Streams.Add(1)
	defer metrics.Streams.Add(-1)

	rw = WithIOMetric(&packetIO{rw}, metrics.IOMetric)

	var (
		log             = c.logger()
		ifaceWriteChan  = c.getIfaceWriteChan()
		tunnelWriteChan chan []byte
		postWrite       = func(<-chan struct{}, error) { metrics.Lags.Add(-1) }
		bufpool         = c
	)
	if localIP.To4() != nil {
		tunnelWriteChan = c.getTunnel4WriteChan()
	} else {
		tunnelWriteChan = c.getTunnel6WriteChan()
	}
	return serveIO(ctx, rw, bufpool, func(done <-chan struct{}, pkt []byte) (retainBuf bool) {
		ver := GetIPPacketVersion(pkt)

		if log.Level() >= LogLevelTrace {
			if ver == 4 {
				log.Tracef("tunnel recv: %s", IPv4Header(pkt))
			} else {
				log.Tracef("tunnel recv: %s", IPv6Header(pkt))
			}
		}

		var dstIP net.IP
		if ver == 4 {
			dstIP = IPv4Header(pkt).Dst()
		} else {
			dstIP = IPv6Header(pkt).Dst()
		}

		if !dstIP.Equal(localIP) {
			log.Tracef("tunnel drop packet: dst %s mismatched", dstIP)
			return
		}

		select {
		case ifaceWriteChan <- pkt:
			retainBuf = true
			return
		case <-done:
			return
		}
	}, tunnelWriteChan, postWrite)
}

func (c *Client) newTransport() (ts http.RoundTripper) {
	// TODO Need a timing to refresh the cached server address (if the DNS results changed)
	var (
		mu           sync.Mutex
		resolvedAddr net.Addr
	)
	return &http2.Transport{
		DialTLS: func(network, addr string, cfg *tls.Config) (conn net.Conn, err error) {
			mu.Lock()
			locked := true
			if resolvedAddr != nil {
				addr = resolvedAddr.String()
				mu.Unlock()
				locked = false
			}
			defer func() {
				if locked {
					mu.Unlock()
				}
			}()

			dial := c.Dial
			if dial == nil {
				dial = net.Dial
			}
			conn, err = dial(network, addr)
			if err != nil {
				return nil, err
			}

			if locked {
				resolvedAddr = conn.RemoteAddr()
				mu.Unlock()
				locked = false
			}

			if !c.UseH2C {
				cn := tls.Client(conn, cfg)
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
				conn = cn
			}

			return conn, nil
		},
		TLSClientConfig: c.TLSConfig,
	}
}

func (c *Client) httpClient() *http.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hc != nil {
		return c.hc
	}
	c.hc = &http.Client{
		Transport: c.newTransport(),
	}
	return c.hc
}

func (c *Client) url(path string) *url.URL {
	return &url.URL{
		Scheme: "https",
		Host:   c.Host,
		Path:   c.URLPrefix + path,
	}
}

func (c *Client) setAuth(r *http.Request) {
	if c.Auth != nil {
		c.Auth(r)
	}
}

func (c *Client) setNoise(r *http.Request) {
	if c.Noise != 0 {
		r.Header.Set(headerNoise, getNoisePadding(c.Noise, r.Method+r.URL.Path))
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

var testHookClientDoReq func(req *http.Request, res *http.Response, err error)

func (c *Client) doReq(req *http.Request) (*http.Response, error) {
	c.setAuth(req)
	c.setNoise(req)

	hc := c.httpClient()
	res, err := hc.Do(req)
	if testHookClientDoReq != nil {
		testHookClientDoReq(req, res, err)
	}
	if err != nil {
		return nil, &ClientAPIError{Err: err, temp: true}
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

func (c *Client) requestIP(ctx context.Context, ipVersion int) (*IPResult, error) {
	req := &http.Request{
		Method: "POST",
		URL:    c.url("/ip/v" + strconv.Itoa(ipVersion)),
		Header: http.Header{
			headerClientID: []string{c.CID},
		},
	}
	res, err := c.doReq(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var result struct {
		IP       string `json:"ip"`
		Notation int    `json:"notation"`
		TTL      int    `json:"ttl"`
		Gateway  string `json:"gateway"`
	}
	err = json.NewDecoder(res.Body).Decode(&result)
	if err != nil {
		temp := true
		if _, ok := err.(*json.SyntaxError); ok {
			temp = false
		}
		return nil, &ClientAPIError{Err: fmt.Errorf("failed to decode ip result, error: %s", err), temp: temp}
	}

	var (
		ip   = net.ParseIP(result.IP)
		mask net.IPMask
		gw   = net.ParseIP(result.Gateway)
	)
	if ip == nil {
		return nil, &ClientAPIError{Err: fmt.Errorf("failed to decode ip (%s)", result.IP), temp: false}
	}
	if ip.To4() != nil {
		if result.Notation > 0 && result.Notation <= 32 {
			mask = net.CIDRMask(result.Notation, 32)
		} else {
			mask = net.CIDRMask(32, 32)
		}
	} else {
		if result.Notation > 0 && result.Notation <= 128 {
			mask = net.CIDRMask(result.Notation, 128)
		} else {
			mask = net.CIDRMask(128, 128)
		}
	}

	return &IPResult{ip, mask, time.Duration(result.TTL) * time.Second, gw}, nil
}

// RequestIPv4 ...
func (c *Client) RequestIPv4(ctx context.Context) (*IPResult, error) {
	return c.requestIP(ctx, 4)
}

// RequestIPv6 ...
func (c *Client) RequestIPv6(ctx context.Context) (*IPResult, error) {
	return c.requestIP(ctx, 6)
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
func (c *Client) OpenTunnel(ctx context.Context, ip net.IP) (tunnel func(context.Context) error, err error) {
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
		return
	}
	return func(ctx context.Context) error {
		return c.serveTunnel(ctx, &httpClientStream{res.Body, w}, ip)
	}, nil
}
