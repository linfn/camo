package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"expvar"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
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

var camoDir = getCamoDir()

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

	logLevel, ok := camo.LogLevelValues[strings.ToUpper(*logLevel)]
	if !ok {
		log.Fatal("invalid log level")
	}

	log := camo.NewLogger(log.New(os.Stderr, "", log.LstdFlags|log.Llongfile), logLevel)

	host := flag.Arg(0)
	if host == "" {
		log.Fatal("empty host")
	}

	if *debug {
		go func() {
			err := http.ListenAndServe(*debugListen, nil)
			if err != http.ErrServerClosed {
				log.Errorf("debug http server exited: %v", err)
			}
		}()
	}

	cid := ensureCID(host, log)

	iface, err := camo.NewTun(*mtu)
	if err != nil {
		log.Fatalf("failed to create tun device: %v", err)
	}
	defer iface.Close()

	c := camo.Client{
		CID:         cid,
		Host:        host,
		ResolveAddr: *resolve,
		Auth: func(r *http.Request) {
			camo.SetAuth(r, getPassword())
		},
		MTU:    *mtu,
		Logger: log,
		UseH2C: *useH2C,
		SetupTunnel: func(localIP net.IP, remoteIP net.IP) (reset func(), err error) {
			err = iface.SetIPv4(localIP.String() + "/32")
			if err != nil {
				return nil, err
			}
			log.Infof("%s(%s) up", iface.Name(), iface.CIDR4())
			return camo.RedirectGateway(iface.Name(), localIP.String(), remoteIP.String())
		},
	}

	expvar.Publish("camo", c.Metrics())

	go func() {
		s := make(chan os.Signal)
		signal.Notify(s, os.Interrupt, syscall.SIGTERM)
		<-s
		c.Close()
	}()

	err = c.Run(iface)
	if err != nil {
		log.Fatal(err)
	}
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

func ensureCID(host string, log camo.Logger) string {
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
