package main

import (
	"expvar"
	"flag"
	"log"
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

var (
	camoDir        = getCamoDir()
	defaultCertDir = camoDir + "/certs"
)

var (
	help          = flag.Bool("h", false, "help")
	addr          = flag.String("listen", ":443", "listen address")
	password      = flag.String("password", "", "Set a password. It is recommended to use the environment variable CAMO_PASSWORD to set the password.")
	ifaceIPv4     = flag.String("ipv4", "10.20.0.1/24", "iface ipv4 cidr")
	mtu           = flag.Int("mtu", camo.DefaultMTU, "mtu")
	autocertHost  = flag.String("autocert-host", "", "hostname")
	autocertDir   = flag.String("autocert-dir", defaultCertDir, "cert cache directory")
	autocertEmail = flag.String("autocert-email", "", "(optional) email address")
	logLevel      = flag.String("log-level", camo.LogLevelTexts[camo.LogLevelInfo], "log level")
	useH2C        = flag.Bool("h2c", false, "use h2c (for debug)")
	enablePProf   = flag.Bool("pprof", false, "enable pprof")
)

func main() {
	flag.Parse()
	if *help {
		flag.Usage()
		return
	}

	logLevel, ok := camo.LogLevelValues[strings.ToUpper(*logLevel)]
	if !ok {
		log.Fatal("invalid log level")
	}

	log := camo.NewLogger(log.New(os.Stderr, "", log.LstdFlags|log.Llongfile), logLevel)

	if !*useH2C {
		if *autocertHost == "" {
			log.Fatal("missing autocert-host")
		}
	}

	password := getPassword()
	if password == "" {
		log.Fatal("missing password")
	}

	iface, err := camo.NewTun(*mtu)
	if err != nil {
		log.Fatalf("failed to create tun device: %v", err)
	}
	defer iface.Close()

	err = iface.SetIPv4(*ifaceIPv4)
	if err != nil {
		log.Panic(err)
	}
	log.Infof("%s(%s) up", iface.Name(), iface.CIDR4())

	resetNAT, err := camo.SetupNAT(iface.Subnet4().String())
	if err != nil {
		log.Panic(err)
	}
	defer resetNAT()

	ipv4Pool := camo.NewSubnetIPPool(iface.Subnet4(), 256)
	ipv4Pool.Use(iface.IPv4(), "")

	srv := camo.Server{
		MTU:      *mtu,
		IPv4Pool: ipv4Pool,
		Logger:   log,
	}

	expvar.Publish("camo", srv.Metrics())

	mux := http.NewServeMux()
	mux.Handle("/", withLog(log, srv.Handler("")))
	mux.Handle("/debug/vars", expvar.Handler())
	if *enablePProf {
		handlePProf(mux)
	}

	handler := camo.WithAuth(mux, password, log)

	hsrv := http.Server{Addr: *addr}
	if *useH2C {
		hsrv.Handler = h2c.NewHandler(handler, &http2.Server{})
	} else {
		certMgr := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(*autocertDir),
			HostPolicy: autocert.HostWhitelist(*autocertHost),
			Email:      *autocertEmail,
		}
		hsrv.TLSConfig = certMgr.TLSConfig()
		hsrv.Handler = handler
	}

	exit := func(e error) {
		hsrv.Close()
		srv.Close()
	}

	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		exit(nil)
	}()

	log.Info("server start")

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		exit(srv.Serve(iface))
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		if hsrv.TLSConfig != nil {
			err = hsrv.ListenAndServeTLS("", "")
		} else {
			err = hsrv.ListenAndServe()
		}
		if err == http.ErrServerClosed {
			err = nil
		}
		exit(err)
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
