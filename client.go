package camo

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"golang.org/x/net/ipv4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Client ...
type Client struct {
	cid        string
	SetupRoute func(dev string, devCIDR string, srvIP string) (cancel func(), err error)

	stop     chan struct{}
	stopOnce sync.Once
}

// NewClient ...
func NewClient(cid string) *Client {
	return &Client{
		cid:        cid,
		SetupRoute: SetupClientDefaultRoute,
		stop:       make(chan struct{}),
	}
}

// CID ...
func (c *Client) CID() string {
	return c.cid
}

// Run ...
func (c *Client) Run(srvAddr string, iface *Iface) error {
	// TODO host 支持
	srvip, _, err := net.SplitHostPort(srvAddr)
	if err != nil {
		return fmt.Errorf("invalid server address: %v", err)
	}

	conn, err := grpc.Dial(srvAddr, grpc.WithInsecure())
	if err != nil {
		return err
	}
	defer conn.Close()
	gc := NewGatewayClient(conn)

	ipResp, err := gc.RequestIP(context.TODO(), &IPReq{
		Cid: c.cid,
	})
	if err != nil {
		return fmt.Errorf("failed to request ip: %v", err)
	}
	ip := net.ParseIP(ipResp.Ip)
	if ip == nil {
		return fmt.Errorf("server response invalid ip (%s)", ipResp.Ip)
	}

	log.Printf("get ip %s", ip)

	err = iface.Up(ip.String() + "/32")
	if err != nil {
		return fmt.Errorf("set iface up error: %v", err)
	}

	log.Printf("(debug) %s(%s) up", iface.Name(), iface.CIDR())

	if c.SetupRoute != nil {
		resetRoute, err := c.SetupRoute(iface.Name(), iface.CIDR(), srvip)
		if err != nil {
			return fmt.Errorf("setup route error: %v", err)
		}
		defer resetRoute()
	}

	return c.forward(gc, iface)
}

func (c *Client) forward(gc GatewayClient, iface *Iface) error {
	stream, err := gc.Open(metadata.AppendToOutgoingContext(context.TODO(), metaClientID, c.cid))
	if err != nil {
		return fmt.Errorf("failed to open stream: %v", err)
	}
	defer stream.CloseSend()

	exited := make(chan struct{})
	defer close(exited)
	go func() {
		select {
		case <-c.stop:
			iface.Close()
		case <-exited:
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer iface.Close()
		for {
			pkt, err := stream.Recv()
			if err != nil {
				log.Println(err)
				return
			}
			packet := pkt.Data
			h, e := ipv4.ParseHeader(packet)
			if e != nil {
				log.Printf("failed to parse ipv4 header %v", e)
				continue
			}
			if h.Version != 4 {
				//log.Println("(debug) drop ip version 6")
				continue
			}
			log.Printf("(debug) iface recv: %s", h)
			n, err := iface.Write(packet)
			if err != nil {
				log.Println(err)
				return
			}
			if n != len(pkt.Data) {
				err = io.ErrShortWrite
				log.Println(err)
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		wg.Done()
		defer stream.CloseSend()
		var buf [defaultIfaceReadBufSize]byte
		for {
			n, err := iface.Read(buf[:])
			if n > 0 {
				packet := buf[:n]
				h, e := ipv4.ParseHeader(packet)
				if e != nil {
					log.Printf("failed to parse ipv4 header %v", e)
					continue
				}
				if h.Version != 4 {
					//log.Println("(debug) drop ip version 6")
					continue
				}
				log.Printf("(debug) iface recv: %s", h)
				err := stream.Send(&Packet{
					Data: buf[:n],
				})
				if err != nil {
					log.Println(err)
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					log.Println(err)
				}
				return
			}
		}
	}()

	wg.Wait()
	return nil
}

// Stop ...
func (c *Client) Stop() {
	c.stopOnce.Do(func() {
		close(c.stop)
	})
}

// SetupClientDefaultRoute 参考 https://www.tinc-vpn.org/examples/redirect-gateway/
func SetupClientDefaultRoute(dev string, devCIDR string, srvIP string) (cancel func(), err error) {
	oldGateway, oldDev, _, err := GetRoute(srvIP)
	if err != nil {
		return nil, err
	}

	var rollbacks []func()
	rollback := func() {
		for i := len(rollbacks) - 1; i >= 0; i-- {
			rollbacks[i]()
		}
	}
	defer func() {
		if err != nil {
			rollback()
		}
	}()

	add := func(ip, gateway, dev string) {
		if err != nil {
			return
		}
		err = AddRoute(ip, gateway, dev)
		if err != nil {
			return
		}
		rollbacks = append(rollbacks, func() { DelRoute(ip) })
		return
	}

	devIP := strings.Split(devCIDR, "/")[0]

	add(srvIP, oldGateway, oldDev)
	add("0.0.0.0/1", devIP, dev)
	add("128.0.0.0/1", devIP, dev)

	if err != nil {
		return nil, err
	}
	return rollback, nil
}
