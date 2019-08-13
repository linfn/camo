package camo

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/ipv4"
)

const (
	defaultClientIfaceWriteChanLen  = 256
	defaultClientTunnelWriteChanLen = 256
	// DefaultConnCount ...
	DefaultConnCount = 1
)

// Client ...
type Client struct {
	CID         string
	Host        string
	ResolveAddr string
	Password    string
	MTU         int
	Conns       int
	SetupRoute  func(dev string, devCIDR string, srvIP string) (reset func(), err error)
	UseH2C      bool

	mu              sync.Mutex
	bufPool         sync.Pool
	ifaceWriteChan  chan []byte
	tunnelWriteChan chan []byte
	doneChan        chan struct{}
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
	if b == nil {
		return make([]byte, c.mtu())
	}
	return b.([]byte)
}

func (c *Client) freeBuffer(b []byte) {
	c.bufPool.Put(b[:cap(b)])
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

// Run ...
func (c *Client) Run(iface *Iface) (err error) {
	defer iface.Close()

	if c.CID == "" {
		return errors.New("empty cid")
	}

	resolvedAddr, err := c.resolveAddr()
	if err != nil {
		return fmt.Errorf("failed to resolve host: %v", err)
	}
	srvip, _, _ := net.SplitHostPort(resolvedAddr)
	log.Printf("server address is %s", resolvedAddr)

	hc := &http.Client{}
	hc.Transport = c.h2Transport(resolvedAddr)

	ip, ttl, err := c.reqIPv4(context.TODO(), hc, nil)
	if err != nil {
		return err
	}

	log.Printf("client get ip (%s) ttl (%d)", ip, ttl)

	err = iface.Up(ip.String() + "/32")
	if err != nil {
		return fmt.Errorf("set iface up error: %v", err)
	}

	log.Printf("(debug) %s(%s) up", iface.Name(), iface.CIDR())

	if c.SetupRoute != nil {
		resetRoute, err := c.SetupRoute(iface.Name(), iface.CIDR(), srvip)
		if err != nil {
			return fmt.Errorf("setup route error: %v", err)
		}
		defer resetRoute()
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
		tunnelWriteChan := c.getTunnelWriteChan()
		h := ipv4.Header{}
		e := serveIO(done, iface, c, c.getIfaceWriteChan(), func(stop <-chan struct{}, pkt []byte) (ok bool, err error) {
			if e := parseIPv4Header(&h, pkt); e != nil {
				log.Printf("iface failed to parse ipv4 header %v", e)
				return
			}
			if h.Version != 4 {
				//log.Printf("(debug) iface drop ip version %d", h.Version)
				return
			}
			log.Printf("(debug) iface recv: %s", &h)
			select {
			case tunnelWriteChan <- pkt:
				ok = true
				return
			case <-stop:
				return
			}
		})
		exit(e)
	}()

	connCount := c.Conns
	if connCount <= 0 {
		connCount = DefaultConnCount
	}
	for i := 0; i < connCount; i++ {
		hc := hc
		// HTTP/2 client only have about one connection per host
		if i > 0 {
			hc = &http.Client{}
			hc.Transport = c.h2Transport(resolvedAddr)
		}
		wg.Add(1)
		go func(hc *http.Client) {
			defer wg.Done()
			exit(c.tunnel(done, hc))
		}(hc)
	}

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

func (c *Client) reqIPv4(ctx context.Context, hc *http.Client, reqIP net.IP) (ip net.IP, ttl time.Duration, err error) {
	var url *url.URL
	if reqIP != nil {
		url = c.url("/ip/v4/" + reqIP.String())
	} else {
		url = c.url("/ip/v4/")
	}

	reqBody, err := json.Marshal(&struct {
		CID string `json:"cid"`
	}{c.CID})
	if err != nil {
		return
	}

	req := &http.Request{
		Method: "POST",
		URL:    url,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: ioutil.NopCloser(bytes.NewReader(reqBody)),
	}
	SetAuth(req, c.Password)
	req.WithContext(ctx)
	res, err := hc.Do(req)
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

func (c *Client) tunnel(stop <-chan struct{}, hc *http.Client) (err error) {
	r, w := io.Pipe()
	req := &http.Request{
		Method: "POST",
		URL:    c.url("/tunnel/" + c.CID),
		Body:   ioutil.NopCloser(r),
	}
	SetAuth(req, c.Password)
	req.WithContext(context.TODO())
	res, err := hc.Do(req)
	if err != nil {
		w.Close()
		err = fmt.Errorf("failed to open tunnel, error: %v", err)
		return
	}
	if res.StatusCode != http.StatusOK {
		w.Close()
		res.Body.Close()
		err = fmt.Errorf("failed to open tunnel, status: %s", res.Status)
		return
	}

	ifaceWriteChan := c.getIfaceWriteChan()
	h := ipv4.Header{}
	return serveIO(stop, &packetIO{&httpClientStream{res.Body, w}}, c, c.getTunnelWriteChan(), func(stop <-chan struct{}, pkt []byte) (ok bool, err error) {
		if e := parseIPv4Header(&h, pkt); e != nil {
			log.Printf("tunnel failed to parse ipv4 header %v", e)
			return
		}
		log.Printf("(debug) tunnel recv: %s", &h)
		select {
		case ifaceWriteChan <- pkt:
			ok = true
			return
		case <-stop:
			return
		}
	})
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

// RedirectDefaultGateway 参考 https://www.tinc-vpn.org/examples/redirect-gateway/
func RedirectDefaultGateway(dev string, devCIDR string, srvIP string) (reset func(), err error) {
	oldGateway, oldDev, _, err := GetRoute(srvIP)
	if err != nil {
		return nil, err
	}

	var rollbacks []func()
	rollback := func() {
		for i := len(rollbacks) - 1; i >= 0; i-- {
			rollbacks[i]()
		}
	}
	defer func() {
		if err != nil {
			rollback()
		}
	}()

	add := func(ip, gateway, dev string) {
		if err != nil {
			return
		}
		err = AddRoute(ip, gateway, dev)
		if err != nil {
			return
		}
		rollbacks = append(rollbacks, func() { DelRoute(ip) })
		return
	}

	devIP := strings.Split(devCIDR, "/")[0]

	add(srvIP, oldGateway, oldDev)
	add("0.0.0.0/1", devIP, dev)
	add("128.0.0.0/1", devIP, dev)

	if err != nil {
		return nil, err
	}
	return rollback, nil
}
