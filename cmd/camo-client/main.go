package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/denisbrodbeck/machineid"
	"github.com/linfn/camo"
	"github.com/rs/xid"
)

var help = flag.Bool("h", false, "help")
var password = flag.String("password", "", "password")
var resolve = flag.String("resolve", "", "provide a custom address for a specific host and port pair")
var mtu = flag.Int("mtu", camo.DefaultMTU, "mtu")
var cid = flag.String("cid", "", "client unique identify")
var logLevel = flag.String("log-level", camo.LogLevelTexts[camo.LogLevelInfo], "log level")
var useH2C = flag.Bool("h2c", false, "use h2c (for debug)")

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

	iface, err := camo.NewTun(*mtu)
	if err != nil {
		log.Panic(err)
	}

	cid := *cid
	if cid == "" {
		cid = getCID(host)
	}

	c := camo.Client{
		CID:         cid,
		Host:        host,
		ResolveAddr: *resolve,
		Password:    *password,
		MTU:         *mtu,
		Logger:      log,
		UseH2C:      *useH2C,
		SetupTunnel: func(localIP net.IP, remoteIP net.IP) (reset func(), err error) {
			err = iface.SetIPv4(localIP.String() + "/32")
			if err != nil {
				return nil, err
			}
			log.Infof("%s(%s) up", iface.Name(), iface.CIDR4())
			return camo.RedirectGateway(iface.Name(), localIP.String(), remoteIP.String())
		},
	}

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

func getCID(srvAddr string) string {
	id, err := machineid.ProtectedID("camo@" + srvAddr)
	if err == nil {
		return id
	}
	return xid.New().String()
}
