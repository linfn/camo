package camo

import (
	"errors"
	"net"
	"runtime"
	"strconv"
	"sync"

	"github.com/songgao/water"
)

// Iface ...
type Iface struct {
	*water.Interface

	ipv4    net.IP
	subnet4 *net.IPNet

	ipv6    net.IP
	subnet6 *net.IPNet

	closeOnce sync.Once
	closeErr  error
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

// MTU ...
func (i *Iface) MTU() int {
	ifi, err := net.InterfaceByName(i.Name())
	if err != nil {
		return 0
	}
	return ifi.MTU
}

// SetIPv4 ...
func (i *Iface) SetIPv4(cidr string, peer net.IP) error {
	if cidr == "" {
		return i.delIPv4()
	}
	ip, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	if ip.To4() == nil {
		return errors.New("not a IPv4")
	}
	i.delIPv4()
	err = addIfaceAddr(i.Name(), cidr, peer.String())
	if err != nil {
		return err
	}
	i.ipv4 = ip
	i.subnet4 = subnet
	return nil
}

// SetIPv6 ...
func (i *Iface) SetIPv6(cidr string) error {
	if cidr == "" {
		return i.delIPv6()
	}
	ip, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	if ip.To4() != nil {
		return errors.New("not a IPv6")
	}
	i.delIPv6()
	err = addIfaceAddr(i.Name(), cidr, "")
	if err != nil {
		return err
	}
	i.ipv6 = ip
	i.subnet6 = subnet
	return nil
}

func (i *Iface) delIPv4() error {
	if i.ipv4 == nil {
		return nil
	}
	err := delIfaceAddr(i.Name(), ToCIDR(i.ipv4, i.subnet4.Mask))
	if err != nil {
		return err
	}
	i.ipv4 = nil
	i.subnet4 = nil
	return nil
}

func (i *Iface) delIPv6() error {
	if i.ipv6 == nil {
		return nil
	}
	err := delIfaceAddr(i.Name(), ToCIDR(i.ipv6, i.subnet6.Mask))
	if err != nil {
		return err
	}
	i.ipv6 = nil
	i.subnet6 = nil
	return nil
}

// CIDR4 ...
func (i *Iface) CIDR4() string {
	return ToCIDR(i.ipv4, i.subnet4.Mask)
}

// CIDR6 ...
func (i *Iface) CIDR6() string {
	return ToCIDR(i.ipv6, i.subnet6.Mask)
}

// IPv4 ...
func (i *Iface) IPv4() net.IP {
	return i.ipv4
}

// IPv6 ...
func (i *Iface) IPv6() net.IP {
	return i.ipv6
}

// Subnet4 ...
func (i *Iface) Subnet4() *net.IPNet {
	return i.subnet4
}

// Subnet6 ...
func (i *Iface) Subnet6() *net.IPNet {
	return i.subnet6
}

// Close ...
func (i *Iface) Close() error {
	i.closeOnce.Do(func() {
		i.closeErr = i.Interface.Close()
	})
	return i.closeErr
}

func setIfaceUp(dev string, mtu int) error {
	switch runtime.GOOS {
	case "darwin", "freebsd":
		return setIfaceUpBSD(dev, mtu)
	default:
		return setIfaceUpIPRoute2(dev, mtu)
	}
}

func addIfaceAddr(dev string, cidr string, peer string) error {
	switch runtime.GOOS {
	case "darwin", "freebsd":
		return addIfaceAddrBSD(dev, cidr, peer)
	default:
		return addIfaceAddrIPRoute2(dev, cidr)
	}
}

func delIfaceAddr(dev string, cidr string) error {
	switch runtime.GOOS {
	case "darwin", "freebsd":
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
	family := "-4"
	if !IsIPv4(cidr) {
		family = "-6"
	}
	return runCmd("ip", family, "address", "add", cidr, "dev", dev)
}

func delIfaceAddrIPRoute2(dev string, cidr string) error {
	family := "-4"
	if !IsIPv4(cidr) {
		family = "-6"
	}
	return runCmd("ip", family, "address", "del", cidr, "dev", dev)
}

func setIfaceUpBSD(dev string, mtu int) error {
	args := []string{dev}
	if mtu != 0 {
		args = append(args, "mtu", strconv.Itoa(mtu))
	}
	args = append(args, "up")
	return runCmd("ifconfig", args...)
}

func addIfaceAddrBSD(dev string, cidr string, peer string) error {
	if IsIPv4(cidr) {
		ip, subnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
		return runCmd("ifconfig", dev, "inet", ip.String(), peer, "netmask", subnet.IP.String(), "alias")
	}
	return runCmd("ifconfig", dev, "inet6", cidr, "alias")
}

func delIfaceAddrBSD(dev string, cidr string) error {
	family := "inet"
	if !IsIPv4(cidr) {
		family = "inet6"
	}
	return runCmd("ifconfig", dev, family, cidr, "-alias")
}
