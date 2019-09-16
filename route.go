package camo

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/linfn/camo/internal/util"
)

// GetRoute ...
func GetRoute(dst string) (gateway string, dev string, err error) {
	switch runtime.GOOS {
	case "darwin", "freebsd":
		return getRouteBSD(dst)
	default:
		return getRouteIPRoute2(dst)
	}
}

// AddRoute ...
func AddRoute(dst string, gateway string, dev string) error {
	switch runtime.GOOS {
	case "darwin", "freebsd":
		return addRouteBSD(dst, gateway, dev)
	default:
		return addRouteIPRoute2(dst, gateway, dev)
	}
}

// DelRoute ...
func DelRoute(dst string, gateway string, dev string) error {
	switch runtime.GOOS {
	case "darwin", "freebsd":
		return delRouteBSD(dst, gateway, dev)
	default:
		return delRouteIPRoute2(dst, gateway, dev)
	}
}

func getRouteIPRoute2(dst string) (gateway string, dev string, err error) {
	family := "-4"
	if !util.IsIPv4(dst) {
		family = "-6"
	}
	b, err := util.RunCmdOutput("ip", family, "route", "get", dst)
	if err != nil {
		return
	}
	_, line, err := bufio.ScanLines(b, false)
	if err != nil {
		err = fmt.Errorf("ip route get %s error: %v", dst, err)
		return
	}
	fields := strings.Fields(string(line))

	getfield := func(fields []string, key string) (string, bool) {
		var i int
		for i = range fields {
			if fields[i] == key {
				break
			}
		}
		i++
		if i >= len(fields) {
			return "", false
		}
		return fields[i], true
	}

	dev, ok := getfield(fields, "dev")
	if !ok {
		err = errors.New("route dev not found")
		return
	}
	gateway, _ = getfield(fields, "via")
	//src, _ = getfield(fields, "src")
	return gateway, dev, nil
}

func addRouteIPRoute2(dst string, gateway string, dev string) error {
	family := "-4"
	if !util.IsIPv4(dst) {
		family = "-6"
	}
	args := []string{family, "route", "add", dst}
	if gateway != "" {
		args = append(args, "via", gateway)
	}
	if dev != "" {
		args = append(args, "dev", dev)
	}
	return util.RunCmd("ip", args...)
}

func delRouteIPRoute2(dst string, gateway string, dev string) error {
	family := "-4"
	if !util.IsIPv4(dst) {
		family = "-6"
	}
	args := []string{family, "route", "del", dst}
	if gateway != "" {
		args = append(args, "via", gateway)
	}
	if dev != "" {
		args = append(args, "dev", dev)
	}
	return util.RunCmd("ip", args...)
}

func getRouteBSD(dst string) (gateway string, dev string, err error) {
	family := "-inet"
	if !util.IsIPv4(dst) {
		family = "-inet6"
	}
	b, err := util.RunCmdOutput("route", "-n", "get", family, dst)
	if err != nil {
		return
	}

	getValue := func(line []byte) string {
		fs := bytes.Fields(line)
		if len(fs) <= 1 {
			return ""
		}
		return string(fs[1])
	}

	for i := 0; i < len(b); {
		n, line, e := bufio.ScanLines(b[i:], true)
		if e != nil {
			err = fmt.Errorf("route get %s error: %v", dst, e)
			return
		}
		i += n
		if bytes.Contains(line, []byte("gateway")) {
			gateway = getValue(line)
		} else if bytes.Contains(line, []byte("interface")) {
			dev = getValue(line)
		}
	}
	if dev == "" {
		err = fmt.Errorf("route get %s not found", dst)
		return
	}
	return gateway, dev, nil
}

func addRouteBSD(dst string, gateway string, _ string) error {
	// If the destination is directly reachable via an interface, the -interface modifier should be specified.
	family := "-inet"
	if !util.IsIPv4(dst) {
		family = "-inet6"
	}
	return util.RunCmd("route", "-n", "add", "-net", family, dst, gateway)
}

func delRouteBSD(dst string, gateway string, _ string) error {
	family := "-inet"
	if !util.IsIPv4(dst) {
		family = "-inet6"
	}
	return util.RunCmd("route", "-n", "delete", "-net", family, dst, gateway)
}

// SetupNAT ...
func SetupNAT(src string) (cancel func() error, err error) {
	cmd := "iptables"
	if !util.IsIPv4(src) {
		cmd = "ip6tables"
	}
	err = util.RunCmd(cmd, "-t", "nat", "-A", "POSTROUTING", "-s", src, "-j", "MASQUERADE")
	if err != nil {
		return nil, err
	}
	return func() error {
		return util.RunCmd(cmd, "-t", "nat", "-D", "POSTROUTING", "-s", src, "-j", "MASQUERADE")
	}, nil
}

// RedirectGateway 参考 https://www.tinc-vpn.org/examples/redirect-gateway/
func RedirectGateway(dev string, gateway string) (reset func() error, err error) {
	var rollback util.Rollback
	defer func() {
		if err != nil {
			rollback.Do()
		}
	}()

	var rollbackErr error
	add := func(ip, gateway, dev string) {
		if err != nil {
			return
		}
		err = AddRoute(ip, gateway, dev)
		if err != nil {
			return
		}
		rollback.Add(func() {
			err := DelRoute(ip, gateway, dev)
			if err != nil && rollbackErr == nil {
				rollbackErr = err
			}
		})
	}

	if util.IsIPv4(gateway) {
		add("0.0.0.0/1", gateway, dev)
		add("128.0.0.0/1", gateway, dev)
	} else {
		add("::/3", gateway, dev)

		// Global Unicast
		add("2000::/4", gateway, dev)
		add("3000::/4", gateway, dev)

		// Unique Local Unicast
		add("fc00::/7", gateway, dev)
	}

	if err != nil {
		return nil, err
	}
	return func() error {
		rollback.Do()
		return rollbackErr
	}, nil
}
