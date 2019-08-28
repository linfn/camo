package main

import (
	"context"
	"crypto/tls"
	"expvar"
	"flag"
	stdlog "log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/linfn/camo"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var defaultCertDir = getCamoDir() + "/certs"

var (
	help          = flag.Bool("help", false, "help")
	addr          = flag.String("listen", ":443", "listen address")
	password      = flag.String("password", "", "Set a password. It is recommended to use the environment variable CAMO_PASSWORD to set the password.")
	mtu           = flag.Int("mtu", camo.DefaultMTU, "tun mtu")
	tunIPv4       = flag.String("ip4", "", "tun ipv4 cidr")
	tunIPv6       = flag.String("ip6", "", "tun ipv6 cidr")
	enableNAT4    = flag.Bool("nat4", false, "enable NAT for IPv4")
	enableNAT6    = flag.Bool("nat6", false, "enable NAT for IPv6")
	autocertHost  = flag.String("autocert-host", "", "hostname")
	autocertDir   = flag.String("autocert-dir", defaultCertDir, "cert cache directory")
	autocertEmail = flag.String("autocert-email", "", "(optional) email address")
	logLevel      = flag.String("log-level", camo.LogLevelTexts[camo.LogLevelInfo], "log level")
	useH2C        = flag.Bool("h2c", false, "use h2c (for debug)")
	enablePProf   = flag.Bool("pprof", false, "enable pprof")
)

var (
	log *camo.LevelLogger
)

func init() {
	flag.Parse()
	if *help {
		return
	}

	initLog()

	if *password == "" {
		*password = os.Getenv("CAMO_PASSWORD")
		if *password == "" {
			log.Fatal("missing password")
		}
	}

	if *tunIPv4 == "" && *tunIPv6 == "" {
		log.Fatal("missing ip4 and ip6 config")
	} else {
		if *tunIPv4 != "" {
			if _, _, err := net.ParseCIDR(*tunIPv4); err != nil {
				log.Fatalf("invalid IPv4 cidr: %v", err)
			}
		}
		if *tunIPv6 != "" {
			if _, _, err := net.ParseCIDR(*tunIPv6); err != nil {
				log.Fatalf("invalid IPv6 cidr: %v", err)
			}
		}
	}

	if !*useH2C && *autocertHost == "" {
		log.Fatal("missing autocert-host")
	}
}

func main() {
	if *help {
		flag.Usage()
		return
	}

	var defers camo.RollBack
	defer defers.Do()

	iface := initTun(&defers)

	ctx, cancel := context.WithCancel(context.Background())

	srv := initServer()

	mux := http.NewServeMux()
	mux.Handle("/", withLog(log, srv.Handler(ctx, "")))
	mux.Handle("/debug/vars", expvar.Handler())
	if *enablePProf {
		handlePProf(mux)
	}

	hsrv := initHTTPServer(camo.WithAuth(mux, *password, log))

	var exitOnce sync.Once
	exit := func(err error) {
		exitOnce.Do(func() {
			hsrv.Close()
			cancel()
			if err != nil {
				log.Errorf("server exits with error %v", err)
			}
		})
	}

	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		log.Infof("receive signal %s", <-c)
		exit(nil)
	}()

	log.Info("server start")

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		exit(srv.ServeIface(ctx, iface))
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if !*useH2C {
			exit(hsrv.ListenAndServeTLS("", ""))
		} else {
			exit(hsrv.ListenAndServe())
		}
	}()

	wg.Wait()
}

func getCamoDir() string {
	dir, err := os.UserCacheDir()
	if err == nil {
		return dir + "/camo"
	}
	return ".camo"
}

func initLog() {
	logLevel, ok := camo.LogLevelValues[strings.ToUpper(*logLevel)]
	if !ok {
		stdlog.Fatal("invalid log level")
	}
	log = camo.NewLogger(stdlog.New(os.Stderr, "", stdlog.LstdFlags|stdlog.Llongfile), logLevel)
}

func initTun(defers *camo.RollBack) *camo.Iface {
	iface, err := camo.NewTun(*mtu)
	if err != nil {
		log.Panicf("failed to create tun device: %v", err)
	}
	defers.Add(func() { iface.Close() })

	log.Infof("tun(%s) up", iface.Name())

	if *tunIPv4 != "" {
		if err := iface.SetIPv4(*tunIPv4); err != nil {
			log.Panicf("failed to set %s IPv4 address %s: %v", iface.Name(), *tunIPv4, err)
		}
		log.Infof("set %s IPv4 address at %s", iface.Name(), *tunIPv4)
	}
	if *tunIPv6 != "" {
		if err := iface.SetIPv6(*tunIPv6); err != nil {
			log.Panicf("failed to set %s IPv6 address %s: %v", iface.Name(), *tunIPv6, err)
		}
		log.Infof("set %s IPv6 address at %s", iface.Name(), *tunIPv6)
	}

	if *enableNAT4 {
		resetNAT4, err := camo.SetupNAT(iface.Subnet4().String())
		if err != nil {
			log.Panicf("failed to setup nat4: %v", err)
		}
		defers.Add(resetNAT4)
	}
	if *enableNAT6 {
		resetNAT6, err := camo.SetupNAT(iface.Subnet6().String())
		if err != nil {
			log.Panicf("failed to setup nat6: %v", err)
		}
		defers.Add(resetNAT6)
	}

	return iface
}

func initServer() *camo.Server {
	srv := &camo.Server{
		MTU:    *mtu,
		Logger: log,
	}
	initIPPool(srv)
	expvar.Publish("camo", srv.Metrics())
	return srv
}

func initIPPool(srv *camo.Server) {
	if *tunIPv4 != "" {
		ip, subnet, err := net.ParseCIDR(*tunIPv4)
		if err != nil {
			log.Panic(err)
		}
		srv.IPv4Pool = camo.NewSubnetIPPool(subnet, 256)
		srv.IPv4Pool.Use(ip, "")
	}

	if *tunIPv6 != "" {
		ip, subnet, err := net.ParseCIDR(*tunIPv6)
		if err != nil {
			log.Panic(err)
		}
		srv.IPv6Pool = camo.NewSubnetIPPool(subnet, 256)
		srv.IPv6Pool.Use(ip, "")
	}
}

func initHTTPServer(handler http.Handler) *http.Server {
	hsrv := &http.Server{Addr: *addr}
	if *useH2C {
		hsrv.Handler = h2c.NewHandler(handler, &http2.Server{})
	} else {
		hsrv.TLSConfig = initTLSConfig()
		hsrv.Handler = handler
	}
	return hsrv
}

func initTLSConfig() *tls.Config {
	certMgr := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(*autocertDir),
		HostPolicy: autocert.HostWhitelist(*autocertHost),
		Email:      *autocertEmail,
	}
	return certMgr.TLSConfig()
}

func withLog(log camo.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug(r.Method, r.URL.String(), r.Proto, r.Header)
		h.ServeHTTP(w, r)
	})
}

func handlePProf(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
}
