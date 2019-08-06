package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/linfn/camo"
	"google.golang.org/grpc"
)

var help = flag.Bool("h", false, "help")
var addr = flag.String("l", ":2019", "listen address")
var ifaceIP = flag.String("ip", "10.20.0.1/24", "iface ip cidr")

func main() {
	flag.Parse()
	if *help {
		flag.Usage()
		return
	}

	log.SetFlags(log.LstdFlags | log.Llongfile)

	iface, err := camo.NewTun()
	if err != nil {
		log.Panicf("failed to create tun device: %v", err)
	}
	defer iface.Close()

	err = iface.Up(*ifaceIP)
	if err != nil {
		log.Panicln(err)
	}
	log.Printf("(debug) %s(%s) up", iface.Name(), iface.CIDR())

	resetnat, err := camo.SetupNAT(iface.Subnet().String())
	if err != nil {
		log.Panicln(err)
	}
	defer resetnat()

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Panicln(err)
	}
	log.Printf("server listen at %s", l.Addr())

	ippool := camo.NewIPPool(&net.IPNet{
		IP:   iface.IP(),
		Mask: iface.Subnet().Mask,
	})

	srv := camo.NewServer(ippool)
	defer srv.Stop()
	go func() {
		// TODO serve iface 异常退出如何处理?
		err := srv.Serve(iface)
		if err != nil {
			log.Println(err)
		}
	}()

	gsrv := grpc.NewServer()
	camo.RegisterGatewayServer(gsrv, srv)

	go func() {
		// TODO grpc server 异常退出如何处理?
		err := gsrv.Serve(l)
		if err != nil {
			log.Println(err)
		}
	}()

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	// TODO 等待任务结束
	gsrv.Stop()
	srv.Stop()
}
