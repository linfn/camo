package camo

import (
	"fmt"
	"net"
	"os/exec"
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
