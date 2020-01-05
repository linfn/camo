package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"expvar"
	"flag"
	"fmt"
	"hash/crc32"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/linfn/camo/pkg/camo"
	"github.com/linfn/camo/pkg/env"
	"github.com/linfn/camo/pkg/machineid"
	"github.com/linfn/camo/pkg/util"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type Server struct {
	flags *flag.FlagSet

	help          bool
	listenAddr    string
	password      string
	mtu           int
	tun4          bool
	tun6          bool
	tunIPv4       string
	tunIPv6       string
	disableNAT4   bool
	disableNAT6   bool
	autocertHost  string
	autocertDir   string
	autocertEmail string
	logLevel      string
	useH2C        bool
	debugHTTP     string

	log camo.Logger
}

func (cmd *Server) flagSet() *flag.FlagSet {
	if cmd.flags != nil {
		return cmd.flags
	}

	fs := flag.NewFlagSet("client", flag.ExitOnError)

	fs.BoolVar(&cmd.help, "h", false, "help")
	fs.StringVar(&cmd.listenAddr, "listen", env.String("CAMO_LISTEN", ":443"), "listen address")
	fs.StringVar(&cmd.password, "password", env.String("CAMO_PASSWORD", ""), "Set a password. It is recommended to use the environment variable CAMO_PASSWORD to set the password.")
	fs.IntVar(&cmd.mtu, "mtu", env.Int("CAMO_MTU", camo.DefaultMTU), "tun mtu")
	fs.BoolVar(&cmd.tun4, "4", env.Bool("CAMO_ENABLE_IP4", false), "tunneling for IPv4")
	fs.BoolVar(&cmd.tun6, "6", env.Bool("CAMO_ENABLE_IP6", false), "tunneling for IPv6")
	fs.StringVar(&cmd.tunIPv4, "ip4", env.String("CAMO_TUN_IP4", "10.20.0.1/24"), "tun IPv4 cidr")
	fs.StringVar(&cmd.tunIPv6, "ip6", env.String("CAMO_TUN_IP6", "fd01:cafe::1/64"), "tun IPv6 cidr")
	fs.BoolVar(&cmd.disableNAT4, "disable-nat4", env.Bool("CAMO_DISABLE_NAT4", false), "disable NAT for IPv4")
	fs.BoolVar(&cmd.disableNAT6, "disable-nat6", env.Bool("CAMO_DISABLE_NAT6", false), "disable NAT for IPv6")
	fs.StringVar(&cmd.autocertHost, "autocert-host", env.String("CAMO_AUTOCERT_HOST", ""), "hostname")
	fs.StringVar(&cmd.autocertDir, "autocert-dir", env.String("CAMO_AUTOCERT_DIR", defaultCertDir), "cert cache directory")
	fs.StringVar(&cmd.autocertEmail, "autocert-email", env.String("CAMO_AUTOCERT_EMAIL", ""), "(optional) email address")
	fs.StringVar(&cmd.logLevel, "log-level", env.String("CAMO_LOG_LEVEL", camo.LogLevelTexts[camo.LogLevelInfo]), "log level")
	fs.BoolVar(&cmd.useH2C, "h2c", env.Bool("CAMO_H2C", false), "use h2c (for debug)")
	fs.StringVar(&cmd.debugHTTP, "debug-http", env.String("CAMO_DEBUG_HTTP", ""), "debug http server listen address")

	cmd.flags = fs
	return fs
}

func (cmd *Server) Name() string {
	return "server"
}

func (cmd *Server) Desc() string {
	return "Run camo server"
}

func (cmd *Server) Usage() {
	fmt.Printf("Usage: camo server [OPTIONS]\n")
	cmd.flagSet().PrintDefaults()
}

func (cmd *Server) parseFlags(args []string) {
	fs := cmd.flagSet()
	_ = fs.Parse(args)
	if cmd.help {
		return
	}

	log := newLogger(cmd.logLevel)
	cmd.log = log

	if cmd.password == "" {
		log.Fatal("missing password")
	}
	hiddenPasswordArg()

	if !cmd.tun4 && !cmd.tun6 {
		cmd.tun4 = true
		cmd.tun6 = true
	}

	if cmd.tun4 {
		if _, _, err := net.ParseCIDR(cmd.tunIPv4); err != nil {
			log.Fatalf("invalid --tun-ip4 cidr: %v", err)
		}
	}
	if cmd.tun6 {
		if _, _, err := net.ParseCIDR(cmd.tunIPv6); err != nil {
			log.Fatalf("invalid --tun-ip6 cidr: %v", err)
		}
	}

	if !cmd.useH2C && cmd.autocertHost == "" {
		log.Info("no auotcert config, use PSK mode")
	}
}

func (cmd *Server) Run(args ...string) {
	cmd.parseFlags(args)
	if cmd.help {
		cmd.Usage()
		return
	}

	log := cmd.log

	var defers util.Rollback
	defer defers.Do()

	iface := cmd.initTun(&defers)

	ctx, cancel := context.WithCancel(context.Background())

	srv := cmd.initServer()

	mux := http.NewServeMux()
	mux.Handle("/", cmd.withLog(srv.Handler(ctx, "")))

	hsrv := cmd.initHTTPServer(camo.WithAuth(mux, cmd.password, log))

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
		if !cmd.useH2C {
			exit(hsrv.ListenAndServeTLS("", ""))
		} else {
			exit(hsrv.ListenAndServe())
		}
	}()

	if cmd.debugHTTP != "" {
		go cmd.debugHTTPServer()
	}

	wg.Wait()
}

func (cmd *Server) initTun(defers *util.Rollback) *camo.Iface {
	log := cmd.log

	iface, err := camo.NewTunIface(cmd.mtu)
	if err != nil {
		log.Panicf("failed to create tun device: %v", err)
	}
	defers.Add(func() { iface.Close() })

	log.Infof("tun(%s) up", iface.Name())

	if cmd.tun4 {
		if err := iface.SetIPv4(cmd.tunIPv4); err != nil {
			log.Panicf("failed to set %s IPv4 address %s: %v", iface.Name(), cmd.tunIPv4, err)
		}
		log.Infof("set %s IPv4 address at %s", iface.Name(), cmd.tunIPv4)

		if !cmd.disableNAT4 {
			resetNAT4, err := camo.SetupNAT(iface.Subnet4().String())
			if err != nil {
				log.Panicf("failed to setup nat4: %v", err)
			}
			defers.Add(func() {
				err := resetNAT4()
				if err != nil {
					log.Error(err)
				}
			})
		}
	}

	if cmd.tun6 {
		if err := iface.SetIPv6(cmd.tunIPv6); err != nil {
			log.Panicf("failed to set %s IPv6 address %s: %v", iface.Name(), cmd.tunIPv6, err)
		}
		log.Infof("set %s IPv6 address at %s", iface.Name(), cmd.tunIPv6)

		if !cmd.disableNAT6 {
			resetNAT6, err := camo.SetupNAT(iface.Subnet6().String())
			if err != nil {
				log.Panicf("failed to setup nat6: %v", err)
			}
			defers.Add(func() {
				err := resetNAT6()
				if err != nil {
					log.Error(err)
				}
			})
		}
	}

	return iface
}

func (cmd *Server) initServer() *camo.Server {
	srv := &camo.Server{
		MTU:    cmd.mtu,
		Logger: cmd.log,
		Noise:  cmd.getNoise(),
	}
	cmd.initIPPool(srv)
	expvar.Publish("camo", srv.Metrics())
	return srv
}

func (cmd *Server) initIPPool(srv *camo.Server) {
	log := cmd.log

	if cmd.tun4 {
		gw, subnet, err := net.ParseCIDR(cmd.tunIPv4)
		if err != nil {
			log.Panic(err)
		}
		srv.IPv4Pool = camo.NewSubnetIPPool(subnet, gw, 256)
	}

	if cmd.tun6 {
		gw, subnet, err := net.ParseCIDR(cmd.tunIPv6)
		if err != nil {
			log.Panic(err)
		}
		srv.IPv6Pool = camo.NewSubnetIPPool(subnet, gw, 256)
	}
}

func (cmd *Server) getNoise() int {
	id, err := machineid.MachineID(getCamoDir())
	if err == nil {
		return int(crc32.ChecksumIEEE([]byte(id)))
	}
	cmd.log.Warnf("failed to get machineid: %v", err)
	return rand.New(rand.NewSource(time.Now().UnixNano())).Int()
}

func (cmd *Server) initHTTPServer(handler http.Handler) *http.Server {
	hsrv := &http.Server{Addr: cmd.listenAddr}
	if cmd.useH2C {
		hsrv.Handler = h2c.NewHandler(handler, &http2.Server{})
	} else {
		hsrv.TLSConfig = cmd.initTLSConfig()
		hsrv.Handler = handler
	}
	return hsrv
}

func (cmd *Server) initTLSConfig() *tls.Config {
	tlsCfg := new(tls.Config)
	tlsCfg.MinVersion = tls.VersionTLS12
	tlsCfg.NextProtos = []string{"h2", "http/1.1"}

	if cmd.autocertHost != "" {
		certMgr := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(cmd.autocertDir),
			HostPolicy: autocert.HostWhitelist(cmd.autocertHost),
			Email:      cmd.autocertEmail,
		}
		tlsCfg.GetCertificate = certMgr.GetCertificate
		tlsCfg.NextProtos = append(tlsCfg.NextProtos, acme.ALPNProto)
	} else {
		tlsCfg.SessionTicketKey = camo.NewSessionTicketKey(cmd.password)
		tlsCfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, errors.New("(PSK) bad certificate")
		}
	}

	return tlsCfg
}

func (cmd *Server) withLog(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd.log.Info(r.Method, r.URL.String(), r.Proto, "remote:", r.RemoteAddr)
		h.ServeHTTP(w, r)
	})
}

func (cmd *Server) debugHTTPServer() {
	err := http.ListenAndServe(cmd.debugHTTP, nil)
	if err != http.ErrServerClosed {
		cmd.log.Errorf("debug http server exited: %v", err)
	}
}
