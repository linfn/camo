package cmd

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"expvar"
	"flag"
	"fmt"
	"hash/crc32"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/linfn/camo/pkg/camo"
	"github.com/linfn/camo/pkg/env"
	"github.com/linfn/camo/pkg/machineid"
	"github.com/linfn/camo/pkg/util"
)

// Client ...
type Client struct {
	flags *flag.FlagSet

	help             bool
	host             string
	password         string
	tun4             bool
	tun6             bool
	resolve          string
	resolve4         bool
	resolve6         bool
	usePSK           bool
	mtu              int
	disableReGateway bool
	logLevel         string
	useH2C           bool
	debugHTTP        string

	log        camo.Logger
	remoteAddr atomic.Value
}

func (cmd *Client) flagSet() *flag.FlagSet {
	if cmd.flags != nil {
		return cmd.flags
	}

	fs := flag.NewFlagSet("client", flag.ExitOnError)

	fs.BoolVar(&cmd.help, "h", false, "help")
	fs.StringVar(&cmd.password, "password", env.String("CAMO_PASSWORD", ""), "Set a password. It is recommended to use the environment variable CAMO_PASSWORD to set the password.")
	fs.BoolVar(&cmd.tun4, "4", env.Bool("CAMO_ENABLE_IP4", false), "tunneling for IPv4")
	fs.BoolVar(&cmd.tun6, "6", env.Bool("CAMO_ENABLE_IP6", false), "tunneling for IPv6")
	fs.StringVar(&cmd.resolve, "resolve", env.String("CAMO_RESOLVE", ""), "provide a custom address for a specific host and port pair")
	fs.BoolVar(&cmd.resolve4, "resolve4", env.Bool("CAMO_RESOLVE4", false), "resolve host name to IPv4 addresses only")
	fs.BoolVar(&cmd.resolve6, "resolve6", env.Bool("CAMO_RESOLVE6", false), "resolve host name to IPv6 addresses only")
	fs.BoolVar(&cmd.usePSK, "psk", env.Bool("CAMO_PSK", false), "use TLS 1.3 PSK mode")
	fs.IntVar(&cmd.mtu, "mtu", env.Int("CAMO_MTU", camo.DefaultMTU), "mtu")
	fs.BoolVar(&cmd.disableReGateway, "disable-redirect-gateway", env.Bool("CAMO_DISABLE_REDIRECT_GATEWAY", false), "dsiable redirect gateway")
	fs.StringVar(&cmd.logLevel, "log-level", env.String("CAMO_LOG_LEVEL", camo.LogLevelTexts[camo.LogLevelInfo]), "log level")
	fs.BoolVar(&cmd.useH2C, "h2c", env.Bool("CAMO_H2C", false), "use h2c (for debug)")
	fs.StringVar(&cmd.debugHTTP, "debug-http", env.String("CAMO_DEBUG_HTTP", ""), "debug http server listen address")

	cmd.flags = fs
	return fs
}

func (cmd *Client) Name() string {
	return "client"
}

func (cmd *Client) Desc() string {
	return "Connect to camo server"
}

func (cmd *Client) Usage() {
	fmt.Printf("Usage: camo client [OPTIONS] <host>\n")
	cmd.flagSet().PrintDefaults()
}

func (cmd *Client) parseFlags(args []string) {
	fs := cmd.flagSet()

	_ = fs.Parse(args)
	if cmd.help {
		return
	}

	log := newLogger(cmd.logLevel)
	cmd.log = log

	cmd.host = fs.Arg(0)
	if cmd.host == "" {
		cmd.host = os.Getenv("CAMO_HOST")
		if cmd.host == "" {
			log.Fatal("missing host")
		}
	}

	if !cmd.tun4 && !cmd.tun6 {
		cmd.tun4 = true
		cmd.tun6 = true
	}

	if cmd.resolve4 && cmd.resolve6 {
		log.Fatal("can not use -resolve4 and -resolve6 at the same time")
	}

	if cmd.resolve != "" {
		addr, err := util.GetHostPortAddr(cmd.resolve, "443")
		if err != nil {
			log.Fatalf("resolve addr %s error: %v", cmd.resolve, err)
		}
		cmd.resolve = addr
	}

	if cmd.usePSK && cmd.useH2C {
		log.Fatal("cannot use both psk mode and h2c mode")
	}

	if cmd.password == "" {
		log.Fatal("missing password")
	}
	hiddenPasswordArg()
}

func (cmd *Client) Run(args ...string) {
	cmd.parseFlags(args)
	if cmd.help {
		cmd.Usage()
		return
	}

	log := cmd.log
	cid := cmd.getCID(cmd.host)

	iface, err := camo.NewTunIface(cmd.mtu)
	if err != nil {
		log.Panicf("failed to create tun device: %v", err)
	}
	defer iface.Close()

	ctx, cancel := context.WithCancel(context.Background())

	c := &camo.Client{
		MTU:       cmd.mtu,
		CID:       cid,
		Host:      cmd.host,
		TLSConfig: cmd.initTLSConfig(),
		Dial: func(network, addr string) (net.Conn, error) {
			if cmd.resolve4 {
				network = "tcp4"
			} else if cmd.resolve6 {
				network = "tcp6"
			}
			if cmd.resolve != "" {
				addr = cmd.resolve
			}
			var d net.Dialer
			conn, err := d.DialContext(ctx, network, addr)
			if err == nil {
				cmd.remoteAddr.Store(conn.RemoteAddr())
				log.Infof("connection succeeded. remote: %s", conn.RemoteAddr())
			}
			return conn, err
		},
		Auth:   func(r *http.Request) { camo.SetAuth(r, cmd.password) },
		Logger: log,
		UseH2C: cmd.useH2C,
		Noise:  cmd.getNoise(cid),
	}

	expvar.Publish("camo", c.Metrics())

	go func() {
		cmd := make(chan os.Signal, 1)
		signal.Notify(cmd, os.Interrupt, syscall.SIGTERM)
		log.Debugf("receive signal %s", <-cmd)
		cancel()
	}()

	if cmd.debugHTTP != "" {
		go cmd.debugHTTPServer()
	}

	cmd.runClient(ctx, c, iface)
}

func (cmd *Client) getCID(host string) string {
	mid, err := machineid.MachineID(camoDir)
	if err != nil {
		cmd.log.Panic(err)
	}
	mac := hmac.New(sha256.New, []byte(mid))
	_, err = mac.Write([]byte("camo@" + host))
	if err != nil {
		cmd.log.Panic(err)
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func (cmd *Client) initTLSConfig() *tls.Config {
	tlsCfg := new(tls.Config)
	tlsCfg.ServerName = util.StripPort(cmd.host)
	if cmd.usePSK {
		cs, err := camo.NewTLSPSKSessionCache(tlsCfg.ServerName, camo.NewSessionTicketKey(cmd.password))
		if err != nil {
			cmd.log.Panicf("failed to init TLS PSK session: %v", err)
		}
		tlsCfg.ClientSessionCache = cs
	} else {
		tlsCfg.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	}
	return tlsCfg
}

func (cmd *Client) getNoise(cid string) int {
	return int(crc32.ChecksumIEEE([]byte(cid)))
}

func (cmd *Client) setupTun(iface *camo.Iface, tunIP net.IP, mask net.IPMask, gateway net.IP) (reset func(), err error) {
	log := cmd.log

	var rollback util.Rollback
	defer func() {
		if err != nil {
			rollback.Do()
		}
	}()
	addRollback := func(f func() error) {
		rollback.Add(func() { _ = f() })
	}

	var (
		cidr     = util.ToCIDR(tunIP, mask)
		tunIPVer int
	)
	if tunIP.To4() != nil {
		tunIPVer = 4
		if err = iface.SetIPv4(cidr); err != nil {
			return nil, err
		}
		addRollback(func() error { return iface.SetIPv4("") })
	} else {
		tunIPVer = 6
		if err = iface.SetIPv6(cidr); err != nil {
			return nil, err
		}
		addRollback(func() error { return iface.SetIPv6("") })
	}
	log.Infof("%s(%s) up", iface.Name(), cidr)

	if !cmd.disableReGateway {
		// bypass tun for server ip
		srvAddr, _ := cmd.remoteAddr.Load().(net.Addr)
		if srvAddr == nil {
			return nil, errors.New("failed to get server address")
		}
		srvIP, _, err := net.SplitHostPort(srvAddr.String())
		if err != nil {
			return nil, fmt.Errorf("failed to get server ip: %v (%s)", err, srvAddr)
		}
		srvIPVer := 4
		if !util.IsIPv4(srvIP) {
			srvIPVer = 6
		}
		if srvIPVer == tunIPVer {
			oldGateway, oldDev, err := camo.GetRoute(srvIP)
			if err != nil {
				return nil, err
			}
			err = camo.AddRoute(srvIP, oldGateway, oldDev)
			if err != nil {
				return nil, err
			}
			addRollback(func() error { return camo.DelRoute(srvIP, oldGateway, oldDev) })
		}

		resetGateway, err := camo.RedirectGateway(iface.Name(), gateway.String())
		if err != nil {
			return nil, err
		}
		addRollback(resetGateway)
	}

	return rollback.Do, nil
}

func (cmd *Client) runClient(ctx context.Context, c *camo.Client, iface *camo.Iface) {
	log := cmd.log

	createTunnel := func(ctx context.Context, ipVersion int) (func(context.Context) error, error) {
		var err error

		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)

		var res *camo.IPResult
		if ipVersion == 4 {
			res, err = c.RequestIPv4(ctx)
		} else {
			res, err = c.RequestIPv6(ctx)
		}
		if err != nil {
			cancel()
			return nil, err
		}

		log.Infof("client get %s", res)

		var (
			ip   = res.IP
			mask = res.Mask
			gw   = res.Gateway
		)

		tunnel, err := c.CreateTunnel(ctx, ip)
		if err != nil {
			cancel()
			return nil, err
		}

		cancel()

		var reset func()
		if ipVersion == 4 && runtime.GOOS == "darwin" {
			reset, err = cmd.setupTun(iface, ip, mask, ip)
		} else {
			reset, err = cmd.setupTun(iface, ip, mask, gw)
		}
		if err != nil {
			_ = tunnel(ctx) // use a canceled ctx to terminate the tunnel
			return nil, fmt.Errorf("setup tunnel error: %v", err)
		}

		return func(ctx context.Context) error {
			defer reset()
			return tunnel(ctx)
		}, nil
	}

	tunneld := func(ctx context.Context, ipVersion int) {
		firstRound := true
		for {
			tunnel, err := createTunnel(ctx, ipVersion)
			if ctx.Err() != nil {
				break
			}
			if err != nil {
				log.Errorf("failed to create IPv%d tunnel: %v", ipVersion, err)
				if ae, ok := err.(*camo.ClientAPIError); ok {
					if !firstRound || ae.Temporary() {
						goto RETRY
					}
				}
				break
			}

			log.Infof("IPv%d tunnel created", ipVersion)

			err = tunnel(ctx)
			if ctx.Err() != nil {
				log.Infof("IPv%d tunnel closed", ipVersion)
				break
			}
			log.Errorf("IPv%d tunnel closed: %v", ipVersion, err)

			firstRound = false

		RETRY:
			if ctx.Err() != nil {
				break
			}
			// TODO exponential backoff
			time.Sleep(1 * time.Second)
		}

		if ctx.Err() == nil {
			log.Errorf("IPv%d tunnel thread exited", ipVersion)
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	exit := cancel

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := c.ServeIface(ctx, iface)
		if ctx.Err() != nil {
			return
		}
		log.Errorf("serve iface exited: %v", err)
		exit()
	}()

	var tunWG sync.WaitGroup

	if cmd.tun4 {
		tunWG.Add(1)
		go func() {
			tunneld(ctx, 4)
			tunWG.Done()
		}()
	}

	if cmd.tun6 {
		tunWG.Add(1)
		go func() {
			tunneld(ctx, 6)
			tunWG.Done()
		}()
	}

	tunWG.Wait()
	if ctx.Err() == nil {
		exit()
	}

	wg.Wait()
}

func (cmd *Client) debugHTTPServer() {
	err := http.ListenAndServe(cmd.debugHTTP, nil)
	if err != http.ErrServerClosed {
		cmd.log.Errorf("debug http server exited: %v", err)
	}
}
