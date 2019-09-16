package main

import (
	"context"
	"crypto/tls"
	"errors"
	"expvar"
	"flag"
	"hash/crc32"
	stdlog "log"
	"math/rand"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/linfn/camo"
	"github.com/linfn/camo/internal/envflag"
	"github.com/linfn/camo/internal/machineid"
	"github.com/linfn/camo/internal/util"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var defaultCertDir = path.Join(getCamoDir(), "certs")

var (
	help          = flag.Bool("help", false, "help")
	listenAddr    = envflag.String("listen", "CAMO_LISTEN", ":443", "listen address")
	password      = envflag.String("password", "CAMO_PASSWORD", "", "Set a password. It is recommended to use the environment variable CAMO_PASSWORD to set the password.")
	mtu           = envflag.Int("mtu", "CAMO_MTU", camo.DefaultMTU, "tun mtu")
	tunIPv4       = envflag.String("tun-ip4", "CAMO_TUN_IP4", "", "tun ipv4 cidr")
	tunIPv6       = envflag.String("tun-ip6", "CAMO_TUN_IP6", "", "tun ipv6 cidr")
	enableNAT     = envflag.Bool("nat", "CAMO_NAT", false, "enable NAT for IPv4 and IPv6")
	enableNAT4    = envflag.Bool("nat4", "CAMO_NAT4", false, "enable NAT for IPv4")
	enableNAT6    = envflag.Bool("nat6", "CAMO_NAT6", false, "enable NAT for IPv6")
	autocertHost  = envflag.String("autocert-host", "CAMO_AUTOCERT_HOST", "", "hostname")
	autocertDir   = envflag.String("autocert-dir", "CAMO_AUTOCERT_DIR", defaultCertDir, "cert cache directory")
	autocertEmail = envflag.String("autocert-email", "CAMO_AUTOCERT_EMAIL", "", "(optional) email address")
	logLevel      = envflag.String("log-level", "CAMO_LOG_LEVEL", camo.LogLevelTexts[camo.LogLevelInfo], "log level")
	useH2C        = envflag.Bool("h2c", "CAMO_H2C", false, "use h2c (for debug)")
	debugHTTP     = envflag.String("debug-http", "CAMO_DEBUG_HTTP", "", "debug http server listen address")
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
		log.Fatal("missing password")
	}
	// hidden the password to expvar and pprof package
	for i := range os.Args {
		if os.Args[i] == "-password" || os.Args[i] == "--password" {
			os.Args[i+1] = "*"
		}
	}

	if *enableNAT {
		*enableNAT4 = true
		*enableNAT6 = true
	}

	if *tunIPv4 == "" && *tunIPv6 == "" {
		log.Fatal("missing --tun-ip4 and --tun-ip6 config")
	} else {
		if *tunIPv4 != "" {
			if _, _, err := net.ParseCIDR(*tunIPv4); err != nil {
				log.Fatalf("invalid --tun-ip4 cidr: %v", err)
			}
		}
		if *tunIPv6 != "" {
			if _, _, err := net.ParseCIDR(*tunIPv6); err != nil {
				log.Fatalf("invalid --tun-ip6 cidr: %v", err)
			}
		}
	}

	if !*useH2C && *autocertHost == "" {
		log.Info("no auotcert config, use PSK mode")
	}
}

func main() {
	if *help {
		flag.Usage()
		return
	}

	var defers util.Rollback
	defer defers.Do()

	iface := initTun(&defers)

	ctx, cancel := context.WithCancel(context.Background())

	srv := initServer()

	mux := http.NewServeMux()
	mux.Handle("/", withLog(log, srv.Handler(ctx, "")))

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
		c := make(chan os.Signal, 1)
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

	if *debugHTTP != "" {
		go debugHTTPServer()
	}

	wg.Wait()
}

func getCamoDir() string {
	dir, err := os.UserCacheDir()
	if err == nil {
		return path.Join(dir, "camo")
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

func initTun(defers *util.Rollback) *camo.Iface {
	iface, err := camo.NewTun(*mtu)
	if err != nil {
		log.Panicf("failed to create tun device: %v", err)
	}
	defers.Add(func() { iface.Close() })

	log.Infof("tun(%s) up", iface.Name())

	if *tunIPv4 != "" {
		if err := iface.SetIPv4(*tunIPv4, nil); err != nil {
			log.Panicf("failed to set %s IPv4 address %s: %v", iface.Name(), *tunIPv4, err)
		}
		log.Infof("set %s IPv4 address at %s", iface.Name(), *tunIPv4)

		if *enableNAT4 {
			resetNAT4, err := camo.SetupNAT(iface.Subnet4().String())
			if err != nil {
				log.Panicf("failed to setup nat4: %v", err)
			}
			defers.Add(resetNAT4)
		}
	}

	if *tunIPv6 != "" {
		if err := iface.SetIPv6(*tunIPv6); err != nil {
			log.Panicf("failed to set %s IPv6 address %s: %v", iface.Name(), *tunIPv6, err)
		}
		log.Infof("set %s IPv6 address at %s", iface.Name(), *tunIPv6)

		if *enableNAT6 {
			resetNAT6, err := camo.SetupNAT(iface.Subnet6().String())
			if err != nil {
				log.Panicf("failed to setup nat6: %v", err)
			}
			defers.Add(resetNAT6)
		}
	}

	return iface
}

func initServer() *camo.Server {
	srv := &camo.Server{
		MTU:    *mtu,
		Logger: log,
		Noise:  getNoise(),
	}
	initIPPool(srv)
	expvar.Publish("camo", srv.Metrics())
	return srv
}

func initIPPool(srv *camo.Server) {
	if *tunIPv4 != "" {
		gw, subnet, err := net.ParseCIDR(*tunIPv4)
		if err != nil {
			log.Panic(err)
		}
		srv.IPv4Pool = camo.NewSubnetIPPool(subnet, gw, 256)
	}

	if *tunIPv6 != "" {
		gw, subnet, err := net.ParseCIDR(*tunIPv6)
		if err != nil {
			log.Panic(err)
		}
		srv.IPv6Pool = camo.NewSubnetIPPool(subnet, gw, 256)
	}
}

func getNoise() int {
	id, err := machineid.MachineID(getCamoDir())
	if err == nil {
		return int(crc32.ChecksumIEEE([]byte(id)))
	}
	log.Warnf("failed to get machineid: %v", err)
	return rand.New(rand.NewSource(time.Now().UnixNano())).Int()
}

func initHTTPServer(handler http.Handler) *http.Server {
	hsrv := &http.Server{Addr: *listenAddr}
	if *useH2C {
		hsrv.Handler = h2c.NewHandler(handler, &http2.Server{})
	} else {
		hsrv.TLSConfig = initTLSConfig()
		hsrv.Handler = handler
	}
	return hsrv
}

func initTLSConfig() *tls.Config {
	tlsCfg := new(tls.Config)
	tlsCfg.MinVersion = tls.VersionTLS12
	tlsCfg.NextProtos = []string{"h2", "http/1.1"}

	if *autocertHost != "" {
		certMgr := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(*autocertDir),
			HostPolicy: autocert.HostWhitelist(*autocertHost),
			Email:      *autocertEmail,
		}
		tlsCfg.GetCertificate = certMgr.GetCertificate
		tlsCfg.NextProtos = append(tlsCfg.NextProtos, acme.ALPNProto)
	} else {
		tlsCfg.SessionTicketKey = camo.NewSessionTicketKey(*password)
		tlsCfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, errors.New("(PSK) bad certificate")
		}
	}

	return tlsCfg
}

func withLog(log camo.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Info(r.Method, r.URL.String(), r.Proto, "remote:", r.RemoteAddr)
		h.ServeHTTP(w, r)
	})
}

func debugHTTPServer() {
	err := http.ListenAndServe(*debugHTTP, nil)
	if err != http.ErrServerClosed {
		log.Errorf("debug http server exited: %v", err)
	}
}
