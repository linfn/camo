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
	"syscall"

	"github.com/denisbrodbeck/machineid"
	"github.com/linfn/camo"
)

var (
	log     *camo.LevelLogger
	camoDir = getCamoDir()
)

var (
	help        = flag.Bool("h", false, "help")
	password    = flag.String("password", "", "Set a password. It is recommended to use the environment variable CAMO_PASSWORD to set the password.")
	resolve     = flag.String("resolve", "", "provide a custom address for a specific host and port pair")
	mtu         = flag.Int("mtu", camo.DefaultMTU, "mtu")
	logLevel    = flag.String("log-level", camo.LogLevelTexts[camo.LogLevelInfo], "log level")
	useH2C      = flag.Bool("h2c", false, "use h2c (for debug)")
	debug       = flag.Bool("debug", false, "enable metric")
	debugListen = flag.String("debug-listen", "localhost:6060", "debug http server listen address")
)

func usage() {
	fmt.Printf("Usage: %s [OPTIONS] host\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.Parse()
	if *help {
		flag.Usage()
		return
	}

	initLog()

	host := flag.Arg(0)
	if host == "" {
		log.Fatal("empty host")
	}

	cid := ensureCID(host)

	resolveAddr := ensureResolveAddr()

	iface, err := camo.NewTun(*mtu)
	if err != nil {
		log.Fatalf("failed to create tun device: %v", err)
	}
	defer iface.Close()

	c := &camo.Client{
		MTU:    *mtu,
		CID:    cid,
		Host:   host,
		Addr:   resolveAddr,
		Auth:   func(r *http.Request) { camo.SetAuth(r, getPassword()) },
		Logger: log,
		UseH2C: *useH2C,
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

	err = camo.RunClient(ctx, c, iface, setupTunnelHandler(c, iface))
	if err != nil && err != context.Canceled {
		log.Fatal(err)
	}
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

func getPassword() string {
	p := *password
	if p != "" {
		return p
	}
	return os.Getenv("CAMO_PASSWORD")
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

func ensureResolveAddr() *net.TCPAddr {
	addr := *resolve
	if addr == "" {
		return nil
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		log.Fatal("resolve addr %s error: %v", addr, err)
	}
	return tcpAddr
}

func setupTunnelHandler(c *camo.Client, iface *camo.Iface) func(net.IP) (reset func(), err error) {
	return func(ip net.IP) (reset func(), err error) {
		var rollback camo.RollBack
		defer func() {
			if err != nil {
				rollback.Do()
			}
		}()

		if ip.To4() != nil {
			err := iface.SetIPv4(ip.String() + "/32")
			if err != nil {
				return nil, err
			}
			rollback.Add(func() { iface.SetIPv4("") })
			log.Infof("%s(%s) up", iface.Name(), iface.CIDR4())

			srvAddr, err := c.ResolveAddr()
			if err != nil {
				return nil, err
			}
			if srvAddr.IP.To4() != nil {
				oldGateway, oldDev, err := camo.GetRoute(srvAddr.IP.String())
				if err != nil {
					return nil, err
				}
				err = camo.AddRoute(srvAddr.IP.String(), oldGateway, oldDev)
				if err != nil {
					return nil, err
				}
				rollback.Add(func() { camo.DelRoute(srvAddr.IP.String(), oldGateway, oldDev) })
			}

			resetGateway, err := camo.RedirectGateway(iface.Name(), ip.String())
			if err != nil {
				return nil, err
			}
			rollback.Add(resetGateway)
		}

		return rollback.Do, nil
	}
}

func debugHTTPServer() {
	err := http.ListenAndServe(*debugListen, nil)
	if err != http.ErrServerClosed {
		log.Errorf("debug http server exited: %v", err)
	}
}
