package camo

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func cmdError(err error, name string, args []string) error {
	var emsg string
	if e, ok := err.(*exec.ExitError); ok && len(e.Stderr) > 0 {
		emsg = strings.TrimSpace(string(e.Stderr))
	} else {
		emsg = err.Error()
	}
	return fmt.Errorf("%s. cmdline: %s %s", emsg, name, strings.Join(args, " "))
}

func runCmd(name string, arg ...string) error {
	_, err := exec.Command(name, arg...).Output()
	if err != nil {
		return cmdError(err, name, arg)
	}
	return nil
}

func runCmdOutput(name string, arg ...string) ([]byte, error) {
	out, err := exec.Command(name, arg...).Output()
	if err != nil {
		return nil, cmdError(err, name, arg)
	}
	return out, nil
}

// Rollback ...
type Rollback []func()

// Add ...
func (r *Rollback) Add(f func()) {
	*r = append(*r, f)
}

// Do ...
func (r Rollback) Do() {
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

// ToCIDR ...
func ToCIDR(ip net.IP, mask net.IPMask) string {
	ones, _ := mask.Size()
	return fmt.Sprintf("%s/%d", ip, ones)
}
