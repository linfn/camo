package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"expvar"
	"flag"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	stdlog "log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/denisbrodbeck/machineid"
	"github.com/linfn/camo"
)

var camoDir = getCamoDir()

var (
	help      = flag.Bool("help", false, "help")
	password  = flag.String("password", "", "Set a password. It is recommended to use the environment variable CAMO_PASSWORD to set the password.")
	inet4     = flag.Bool("4", false, "resolve host name to IPv4 addresses only")
	inet6     = flag.Bool("6", false, "resolve host name to IPv6 addresses only")
	resolve   = flag.String("resolve", "", "provide a custom address for a specific host and port pair")
	mtu       = flag.Int("mtu", camo.DefaultMTU, "mtu")
	logLevel  = flag.String("log-level", camo.LogLevelTexts[camo.LogLevelInfo], "log level")
	useH2C    = flag.Bool("h2c", false, "use h2c (for debug)")
	debugHTTP = flag.String("debug-http", "", "debug http server listen address")
)

var (
	log        *camo.LevelLogger
	host       string
	cid        string
	remoteAddr atomic.Value
)

func init() {
	flag.Usage = func() {
		fmt.Printf("Usage: %s [OPTIONS] host\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	if *help {
		return
	}

	initLog()

	host = flag.Arg(0)
	if host == "" {
		log.Fatal("missing host")
	}

	if *inet4 && *inet6 {
		log.Fatal("can not use -4 and -6 at the same time")
	}

	if *resolve != "" {
		addr, err := camo.GetHostPortAddr(*resolve, "443")
		if err != nil {
			log.Fatalf("resolve addr %s error: %v", *resolve, err)
		}
		*resolve = addr
	}

	if *password == "" {
		*password = os.Getenv("CAMO_PASSWORD")
		if *password == "" {
			log.Fatal("missing password")
		}
	} else {
		// hidden the password to expvar and pprof package
		for i := range os.Args {
			if os.Args[i] == "-password" || os.Args[i] == "--password" {
				os.Args[i+1] = "*"
			}
		}
	}

	cid = ensureCID(host)
}

func main() {
	if *help {
		flag.Usage()
		return
	}

	iface, err := camo.NewTun(*mtu)
	if err != nil {
		log.Fatalf("failed to create tun device: %v", err)
	}
	defer iface.Close()

	c := &camo.Client{
		MTU:  *mtu,
		CID:  cid,
		Host: host,
		Dial: func(network, addr string) (net.Conn, error) {
			if *inet4 {
				network = "tcp4"
			} else if *inet6 {
				network = "tcp6"
			}
			if *resolve != "" {
				addr = *resolve
			}
			conn, err := net.Dial(network, addr)
			if err == nil {
				remoteAddr.Store(conn.RemoteAddr())
			}
			return conn, err
		},
		Auth:   func(r *http.Request) { camo.SetAuth(r, *password) },
		Logger: log,
		UseH2C: *useH2C,
		Noise:  getNoise(),
	}

	expvar.Publish("camo", c.Metrics())

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		log.Debugf("receive signal %s", <-c)
		cancel()
	}()

	if *debugHTTP != "" {
		go debugHTTPServer()
	}

	runClient(ctx, c, iface)
}

func initLog() {
	logLevel, ok := camo.LogLevelValues[strings.ToUpper(*logLevel)]
	if !ok {
		stdlog.Fatal("invalid log level")
	}
	log = camo.NewLogger(stdlog.New(os.Stderr, "", stdlog.LstdFlags|stdlog.Llongfile), logLevel)
}

func getCamoDir() string {
	dir, err := os.UserCacheDir()
	if err == nil {
		return dir + "/camo"
	}
	return ".camo"
}

func ensureCamoDir() {
	err := os.MkdirAll(camoDir, os.ModePerm)
	if err != nil {
		log.Panicf("failed to create camo dir. path: %s, error: %v", camoDir, err)
	}
}

func ensureCID(host string) string {
	id, err := machineid.ProtectedID("camo@" + host)
	if err == nil {
		return id
	}
	log.Warnf("failed to get protected machineid: %v", err)

	cidFile := camoDir + "/cid"

	b, err := ioutil.ReadFile(cidFile)
	if err != nil && !os.IsNotExist(err) {
		log.Fatalf("failed to read cid file. path: %s, error: %v", cidFile, err)
	}
	if len(b) == 0 {
		b = make([]byte, 32)
		if _, err = rand.Read(b); err != nil {
			log.Fatalf("failed to generate rand: %v", err)
		}
		ensureCamoDir()
		err = ioutil.WriteFile(cidFile, b, os.ModePerm)
		if err != nil {
			log.Fatalf("failed to save cid file. path: %s, error: %v", cidFile, err)
		}
		log.Debugf("cid file saved. path: %s", cidFile)
	}

	log.Debugf("load cid from %s", cidFile)

	mac := hmac.New(sha256.New, b)
	mac.Write([]byte("camo@" + host))
	return hex.EncodeToString(mac.Sum(nil))
}

func getNoise() int {
	return int(crc32.ChecksumIEEE([]byte(cid)))
}

func setupTunHandler(c *camo.Client, iface *camo.Iface) func(net.IP, net.IPMask) (func(), error) {
	return func(tunIP net.IP, mask net.IPMask) (reset func(), err error) {
		var rollback camo.Rollback
		defer func() {
			if err != nil {
				rollback.Do()
			}
		}()

		var (
			cidr     = camo.ToCIDR(tunIP, mask)
			tunIPVer int
		)
		if tunIP.To4() != nil {
			tunIPVer = 4
			if err = iface.SetIPv4(cidr); err != nil {
				return nil, err
			}
			rollback.Add(func() { iface.SetIPv4("") })
		} else {
			tunIPVer = 6
			if err = iface.SetIPv6(cidr); err != nil {
				return nil, err
			}
			rollback.Add(func() { iface.SetIPv6("") })
		}
		log.Infof("%s(%s) up", iface.Name(), cidr)

		// bypass tun for server ip

		srvAddr, _ := remoteAddr.Load().(net.Addr)
		if srvAddr == nil {
			return nil, errors.New("failed to get server address")
		}
		srvIP, _, err := net.SplitHostPort(srvAddr.String())
		if err != nil {
			return nil, fmt.Errorf("failed to get server ip: %v (%s)", err, srvAddr)
		}
		srvIPVer := 4
		if !camo.IsIPv4(srvIP) {
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
			rollback.Add(func() { camo.DelRoute(srvIP, oldGateway, oldDev) })
		}

		resetGateway, err := camo.RedirectGateway(iface.Name(), tunIP.String())
		if err != nil {
			return nil, err
		}
		rollback.Add(resetGateway)

		return rollback.Do, nil
	}
}

func runClient(ctx context.Context, c *camo.Client, iface *camo.Iface) {
	openTunnel := func(ctx context.Context, ipVersion int) (func(context.Context) error, error) {
		var err error

		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)

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
		)

		tunnel, err := c.OpenTunnel(ctx, ip)
		if err != nil {
			cancel()
			return nil, err
		}

		cancel()

		reset, err := setupTunHandler(c, iface)(ip, mask)
		if err != nil {
			tunnel(ctx) // use a canceled ctx to terminate the tunnel
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
			tunnel, err := openTunnel(ctx, ipVersion)
			if ctx.Err() != nil {
				break
			}
			if err != nil {
				log.Errorf("failed to open IPv%d tunnel: %v", ipVersion, err)
				if ae, ok := err.(*camo.ClientAPIError); ok {
					if !firstRound || ae.Temporary() {
						goto RETRY
					}
				}
				break
			}

			log.Infof("IPv%d tunnel opened", ipVersion)

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
			c.FlushResolvedAddr()
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

	tunWG.Add(1)
	go func() {
		tunneld(ctx, 4)
		tunWG.Done()
	}()
	tunWG.Add(1)
	go func() {
		tunneld(ctx, 6)
		tunWG.Done()
	}()

	tunWG.Wait()
	if ctx.Err() == nil {
		exit()
	}

	wg.Wait()
	return
}

func debugHTTPServer() {
	err := http.ListenAndServe(*debugHTTP, nil)
	if err != http.ErrServerClosed {
		log.Errorf("debug http server exited: %v", err)
	}
}
