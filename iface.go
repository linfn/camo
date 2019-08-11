package camo

import (
	"fmt"
	"net"
	"sync"

	"github.com/songgao/water"
)

// TODO MTU

// Iface ...
type Iface struct {
	*water.Interface
	cidr      string
	ip        net.IP
	subnet    *net.IPNet
	closeOnce sync.Once
}

// NewTun ...
func NewTun() (*Iface, error) {
	iface, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		return nil, err
	}
	return &Iface{
		Interface: iface,
	}, nil
}

// Up ...
func (i *Iface) Up(cidr string) error {
	ip, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	err = setIfaceUp(i.Name(), cidr)
	if err != nil {
		return err
	}
	i.cidr = cidr
	i.ip = ip
	i.subnet = subnet
	return nil
}

// Down ...
func (i *Iface) Down() error {
	if i.cidr != "" {
		err := setIfaceDown(i.Name(), i.cidr)
		i.ip = nil
		i.subnet = nil
		return err
	}
	return nil
}

// CIDR ...
func (i *Iface) CIDR() string {
	return i.cidr
}

// IP ...
func (i *Iface) IP() net.IP {
	return i.ip
}

// Subnet ...
func (i *Iface) Subnet() *net.IPNet {
	return i.subnet
}

// MTU ..
func (i *Iface) MTU() int {
	ifi, err := net.InterfaceByName(i.Name())
	if err != nil {
		return 0
	}
	return ifi.MTU
}

// Close ...
func (i *Iface) Close() error {
	var err error
	i.closeOnce.Do(func() {
		i.Down()
		err = i.Interface.Close()
	})
	return err
}

func setIfaceUp(dev string, cidr string) error {
	err := runCmd("ip", "link", "set", dev, "up")
	if err != nil {
		return fmt.Errorf("ip link set %s up error: %v", dev, err)
	}
	if cidr != "" {
		err = runCmd("ip", "addr", "add", cidr, "dev", dev)
		if err != nil {
			setIfaceDown(dev, "")
			return fmt.Errorf("ip addr add %s dev %s error: %v", cidr, dev, err)
		}
	}
	return nil
}

func setIfaceDown(dev string, cidr string) error {
	if cidr != "" {
		runCmd("ip", "addr", "del", cidr, "dev", dev)
	}
	err := runCmd("ip", "link", "set", dev, "down")
	if err != nil {
		return fmt.Errorf("ip link set %s down error: %v", dev, err)
	}
	return nil
}
