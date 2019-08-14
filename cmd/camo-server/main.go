package main

import (
	"flag"
	"log"
	"net"
	"net/http"
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

var help = flag.Bool("h", false, "help")
var addr = flag.String("l", ":443", "listen address")
var password = flag.String("password", "", "password")
var ifaceIP = flag.String("ip", "10.20.0.1/24", "iface ip cidr")
var autocertHost = flag.String("autocert-host", "", "hostname")
var autocertDir = flag.String("autocert-dir", ".certs", "cert cache directory")
var autocertEmail = flag.String("autocert-email", "", "(optional) email address")
var logLevel = flag.String("log-level", camo.LogLevelTexts[camo.LogLevelInfo], "log level")
var useH2C = flag.Bool("h2c", false, "use h2c (for debug) ")

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

	iface, err := camo.NewTun()
	if err != nil {
		log.Fatalf("failed to create tun device: %v", err)
	}
	defer iface.Close()

	err = iface.Up(*ifaceIP)
	if err != nil {
		log.Panic(err)
	}
	log.Infof("%s(%s) up", iface.Name(), iface.CIDR())

	resetNAT, err := camo.SetupNAT(iface.Subnet().String())
	if err != nil {
		log.Panic(err)
	}
	defer resetNAT()

	srv := camo.Server{
		IPv4Pool: camo.NewIPPool(&net.IPNet{
			IP:   iface.IP(),
			Mask: iface.Subnet().Mask,
		}),
		Logger: log,
	}
	handler := camo.WithAuth(srv.Handler(""), *password)

	hsrv := http.Server{Addr: *addr}
	if *useH2C {
		hsrv.Handler = h2c.NewHandler(withLog(handler), &http2.Server{})
	} else {
		certMgr := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(*autocertDir),
			HostPolicy: autocert.HostWhitelist(*autocertHost),
			Email:      *autocertEmail,
		}
		hsrv.TLSConfig = certMgr.TLSConfig()
		hsrv.Handler = withLog(handler)
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

func withLog(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method, r.URL.String(), r.Proto, r.Header)
		h.ServeHTTP(w, r)
	})
}
