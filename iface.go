package camo

import (
	"net"
	"runtime"
	"strconv"
	"sync"

	"github.com/songgao/water"
)

// Iface ...
type Iface struct {
	*water.Interface
	mtu       int
	cidr4     string
	ipv4      net.IP
	subnet4   *net.IPNet
	closeOnce sync.Once
}

// NewTun ...
func NewTun(mtu int) (*Iface, error) {
	iface, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		return nil, err
	}
	err = setIfaceUp(iface.Name(), mtu)
	if err != nil {
		iface.Close()
		return nil, err
	}
	return &Iface{
		Interface: iface,
	}, nil
}

// SetIPv4 ...
func (i *Iface) SetIPv4(cidr string) error {
	ip, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	if i.ipv4 != nil {
		delIfaceAddr(i.Name(), cidr)
	}
	err = addIfaceAddr(i.Name(), cidr)
	if err != nil {
		return err
	}
	i.cidr4 = cidr
	i.ipv4 = ip
	i.subnet4 = subnet
	return nil
}

// CIDR4 ...
func (i *Iface) CIDR4() string {
	return i.cidr4
}

// IPv4 ...
func (i *Iface) IPv4() net.IP {
	return i.ipv4
}

// Subnet4 ...
func (i *Iface) Subnet4() *net.IPNet {
	return i.subnet4
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
		err = i.Interface.Close()
	})
	return err
}

func setIfaceUp(dev string, mtu int) error {
	switch runtime.GOOS {
	case "darwin":
		return setIfaceUpBSD(dev, mtu)
	default:
		return setIfaceUpIPRoute2(dev, mtu)
	}
}

func addIfaceAddr(dev string, cidr string) error {
	switch runtime.GOOS {
	case "darwin":
		return addIfaceAddrBSD(dev, cidr)
	default:
		return addIfaceAddrIPRoute2(dev, cidr)
	}
}

func delIfaceAddr(dev string, cidr string) error {
	switch runtime.GOOS {
	case "darwin":
		return delIfaceAddrBSD(dev, cidr)
	default:
		return delIfaceAddrIPRoute2(dev, cidr)
	}
}

func setIfaceUpIPRoute2(dev string, mtu int) error {
	args := []string{"link", "set", dev, "up"}
	if mtu != 0 {
		args = append(args, "mtu", strconv.Itoa(mtu))
	}
	return runCmd("ip", args...)
}

func addIfaceAddrIPRoute2(dev string, cidr string) error {
	return runCmd("ip", "address", "add", cidr, "dev", dev)
}

func delIfaceAddrIPRoute2(dev string, cidr string) error {
	return runCmd("ip", "address", "del", cidr, "dev", dev)
}

func setIfaceUpBSD(dev string, mtu int) error {
	args := []string{dev}
	if mtu != 0 {
		args = append(args, "mtu", strconv.Itoa(mtu))
	}
	args = append(args, "up")
	return runCmd("ifconfig", args...)
}

func addIfaceAddrBSD(dev string, cidr string) error {
	ip, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	return runCmd("ifconfig", dev, ip.String(), ip.String(), "netmask", subnet.IP.String())
}

func delIfaceAddrBSD(dev string, cidr string) error {
	return runCmd("ifconfig", dev, "inet", cidr, "-alias")
}
