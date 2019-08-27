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
	MTU         int
	CID         string
	Host        string
	ResolveAddr string
	TLSConfig   *tls.Config
	URLPrefix   string
	Auth        func(r *http.Request)
	Logger      Logger
	UseH2C      bool

	mu              sync.Mutex
	bufPool         sync.Pool
	ifaceWriteChan  chan []byte
	tunnelWriteChan chan []byte

	hc *httpClient

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

		var dstIP net.IP
		if ver == 4 {
			dstIP = IPv4Header(pkt).Dst()
		} else {
			dstIP = IPv6Header(pkt).Dst()
		}

		if !dstIP.IsGlobalUnicast() {
			log.Tracef("iface drop packet: not a global unicast, dstIP %s", dstIP)
			return
		}

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

func (c *Client) serveTunnel(ctx context.Context, rw io.ReadWriteCloser, localIP net.IP) error {
	metrics := c.Metrics().Tunnels

	metrics.Streams.Add(1)
	defer metrics.Streams.Add(-1)

	rw = WithIOMetric(&packetIO{rw}, metrics.IOMetric)

	var (
		log            = c.logger()
		ifaceWriteChan = c.getIfaceWriteChan()
		postWrite      = func(<-chan struct{}, error) { metrics.Lags.Add(-1) }
		bufpool        = c
	)
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
	}, c.getTunnelWriteChan(), postWrite)
}

type httpClient struct {
	http.Client
	remoteAddr net.Addr
}

func (c *Client) newTransport(hc *httpClient) (ts http.RoundTripper) {
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
			} else {
				if c.ResolveAddr != "" {
					addr, err = GetHostPortAddr(c.ResolveAddr, "443")
					if err != nil {
						mu.Unlock()
						return nil, err
					}
				}
			}
			defer func() {
				if locked {
					mu.Unlock()
				}
			}()

			conn, err = net.Dial(network, addr)
			if err != nil {
				return nil, err
			}

			if locked {
				resolvedAddr = conn.RemoteAddr()
				mu.Unlock()
				locked = false

				hc.remoteAddr = resolvedAddr
			}

			if !c.UseH2C {
				// http2: Transport.dialTLSDefault
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

func (c *Client) httpClient() *httpClient {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hc != nil {
		return c.hc
	}
	c.hc = new(httpClient)
	c.hc.Transport = c.newTransport(c.hc)
	return c.hc
}

// FlushResolvedAddr ...
func (c *Client) FlushResolvedAddr() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.hc != nil {
		c.hc.CloseIdleConnections()
		c.hc = nil
	}
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

type contextKey int

var keyGetClientRemoteAddr contextKey

func (c *Client) doReq(req *http.Request) (*http.Response, error) {
	c.setAuth(req)

	hc := c.httpClient()
	res, err := hc.Do(req)
	if err != nil {
		temp := true
		if req.Context().Err() != nil {
			temp = false
		}
		return nil, &ClientAPIError{Err: err, temp: temp}
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

	if pAddr, ok := req.Context().Value(keyGetClientRemoteAddr).(*net.Addr); ok {
		*pAddr = hc.remoteAddr
	}

	return res, nil
}

func (c *Client) requestIP(ctx context.Context, ipVersion int) (ip net.IP, ttl time.Duration, err error) {
	req := &http.Request{
		Method: "POST",
		URL:    c.url("/ip/v" + strconv.Itoa(ipVersion)),
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
		temp := true
		if _, ok := err.(*json.SyntaxError); ok {
			temp = false
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

// RequestIPv4 ...
func (c *Client) RequestIPv4(ctx context.Context) (ip net.IP, ttl time.Duration, err error) {
	return c.requestIP(ctx, 4)
}

// RequestIPv6 ...
func (c *Client) RequestIPv6(ctx context.Context) (ip net.IP, ttl time.Duration, err error) {
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
func (c *Client) OpenTunnel(ctx context.Context, ip net.IP) (tunnel func(context.Context) error, remoteAddr net.Addr, err error) {
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
	res, err := c.doReq(req.WithContext(context.WithValue(context.TODO(), keyGetClientRemoteAddr, &remoteAddr)))
	if err != nil {
		w.Close()
		return
	}
	return func(ctx context.Context) error {
		return c.serveTunnel(ctx, &httpClientStream{res.Body, w}, ip)
	}, remoteAddr, nil
}
