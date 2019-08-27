package camo

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func runCmd(name string, arg ...string) error {
	err := exec.Command(name, arg...).Run()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok && len(e.Stderr) > 0 {
			return fmt.Errorf("%v: %s", e, string(e.Stderr))
		}
	}
	return err
}

func runCmdOutput(name string, arg ...string) ([]byte, error) {
	out, err := exec.Command(name, arg...).Output()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok && len(e.Stderr) > 0 {
			return out, fmt.Errorf("%v: %s", e, string(e.Stderr))
		}
	}
	return out, err
}

// RollBack ...
type RollBack []func()

// Add ...
func (r *RollBack) Add(f func()) {
	*r = append(*r, f)
}

// Do ...
func (r RollBack) Do() {
	for i := len(r) - 1; i >= 0; i-- {
		r[i]()
	}
}

// GetHostPortAddr ...
func GetHostPortAddr(addr string, defaultPort string) (string, error) {
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		addr = net.JoinHostPort(addr, defaultPort)
		_, _, err := net.SplitHostPort(addr)
		if err != nil {
			return "", err
		}
	}
	return addr, nil
}

// IsIPv4 ...
func IsIPv4(ip string) bool {
	if strings.Index(ip, "/") >= 0 {
		netIP, _, err := net.ParseCIDR(ip)
		if err != nil {
			return false
		}
		return netIP.To4() != nil
	}
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return false
	}
	return netIP.To4() != nil
}

func toCIDR(ip net.IP, mask net.IPMask) string {
	ones, _ := mask.Size()
	return fmt.Sprintf("%s/%d", ip, ones)
}
