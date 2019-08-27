package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"expvar"
	"flag"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/denisbrodbeck/machineid"
	"github.com/linfn/camo"
)

var camoDir = getCamoDir()

var (
	help        = flag.Bool("help", false, "help")
	password    = flag.String("password", "", "Set a password. It is recommended to use the environment variable CAMO_PASSWORD to set the password.")
	resolve     = flag.String("resolve", "", "provide a custom address for a specific host and port pair")
	mtu         = flag.Int("mtu", camo.DefaultMTU, "mtu")
	logLevel    = flag.String("log-level", camo.LogLevelTexts[camo.LogLevelInfo], "log level")
	useH2C      = flag.Bool("h2c", false, "use h2c (for debug)")
	debug       = flag.Bool("debug", false, "enable metric and pprof")
	debugListen = flag.String("debug-listen", "localhost:6060", "debug http server listen address")
)

var (
	log  *camo.LevelLogger
	host string
	cid  string
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

	if *resolve != "" {
		addr, err := camo.GetHostPortAddr(*resolve, "443")
		if err != nil {
			log.Fatal("resolve addr %s error: %v", *resolve, err)
		}
		*resolve = addr
	}

	if *password == "" {
		*password = os.Getenv("CAMO_PASSWORD")
		if *password == "" {
			log.Fatal("missing password")
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
		MTU:         *mtu,
		CID:         cid,
		Host:        host,
		ResolveAddr: *resolve,
		Auth:        func(r *http.Request) { camo.SetAuth(r, *password) },
		Logger:      log,
		UseH2C:      *useH2C,
	}

	expvar.Publish("camo", c.Metrics())

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		log.Debugf("receive signal %s", <-c)
		cancel()
	}()

	if *debug {
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

func setupTunHandler(c *camo.Client, iface *camo.Iface) func(net.IP, net.Addr) (reset func(), err error) {
	return func(tunIP net.IP, remoteAddr net.Addr) (reset func(), err error) {
		var rollback camo.RollBack
		defer func() {
			if err != nil {
				rollback.Do()
			}
		}()

		var (
			cidr     string
			tunIPVer int
		)
		if tunIP.To4() != nil {
			tunIPVer = 4
			cidr = tunIP.String() + "/32"
			if err = iface.SetIPv4(cidr); err != nil {
				return nil, err
			}
			rollback.Add(func() { iface.SetIPv4("") })
		} else {
			tunIPVer = 6
			cidr = tunIP.String() + "/128"
			if err = iface.SetIPv6(cidr); err != nil {
				return nil, err
			}
			rollback.Add(func() { iface.SetIPv6("") })
		}
		log.Infof("%s(%s) up", iface.Name(), cidr)

		srvIP, _, err := net.SplitHostPort(remoteAddr.String())
		if err != nil {
			return nil, err
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

		var (
			ip  net.IP
			ttl time.Duration
		)
		if ipVersion == 4 {
			ip, ttl, err = c.RequestIPv4(ctx)
		} else {
			ip, ttl, err = c.RequestIPv6(ctx)
		}
		if err != nil {
			cancel()
			return nil, err
		}

		log.Infof("client get ip (%s) ttl (%d)", ip, ttl)

		tunnel, remoteAddr, err := c.OpenTunnel(ctx, ip)
		if err != nil {
			cancel()
			return nil, err
		}

		cancel()

		reset, err := setupTunHandler(c, iface)(ip, remoteAddr)
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
				log.Errorf("failed to open tunnel: %v", err)
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
	err := http.ListenAndServe(*debugListen, nil)
	if err != http.ErrServerClosed {
		log.Errorf("debug http server exited: %v", err)
	}
}
