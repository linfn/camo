package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/denisbrodbeck/machineid"
	"github.com/linfn/camo"
	"github.com/rs/xid"
)

var help = flag.Bool("h", false, "help")
var cid = flag.String("cid", "", "cid")

func usage() {
	fmt.Printf("Usage: %s [OPTIONS] server_address\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.Parse()
	if *help {
		flag.Usage()
		return
	}
	addr := flag.Arg(0)
	if addr == "" {
		log.Panicln("server address empty")
	}

	log.SetFlags(log.LstdFlags | log.Llongfile)

	iface, err := camo.NewTun()
	if err != nil {
		log.Panicln(err)
	}
	defer iface.Close()

	cid := *cid
	if cid == "" {
		cid = getCID(addr)
	}

	c := camo.NewClient(cid)
	go func() {
		s := make(chan os.Signal)
		signal.Notify(s, os.Interrupt, syscall.SIGTERM)
		<-s
		c.Stop()
	}()

	err = c.Run(addr, iface)
	if err != nil {
		log.Println(err)
	}
}

func getCID(srvAddr string) string {
	id, err := machineid.ProtectedID("camo@" + srvAddr)
	if err == nil {
		return id
	}
	return xid.New().String()
}
