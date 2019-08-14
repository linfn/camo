package camo

import (
	"bufio"
	"errors"
	"fmt"
	"strings"
)

// GetRoute ...
func GetRoute(ip string) (gateway string, dev string, src string, err error) {
	b, err := runCmdOutput("ip", "route", "get", ip)
	if err != nil {
		return "", "", "", fmt.Errorf("ip route get %s error: %v", ip, err)
	}
	_, line, err := bufio.ScanLines(b, false)
	if err != nil {
		return "", "", "", fmt.Errorf("ip route get %s error: %v", ip, err)
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
		return "", "", "", errors.New("route dev not found")
	}
	gateway, _ = getfield(fields, "via")
	src, _ = getfield(fields, "src")
	return gateway, dev, src, nil
}

// AddRoute ...
func AddRoute(ip string, gateway string, dev string) error {
	args := []string{"route", "add", ip}
	if gateway != "" {
		args = append(args, "via", gateway)
	}
	if dev != "" {
		args = append(args, "dev", dev)
	}
	err := runCmd("ip", args...)
	if err != nil {
		err = fmt.Errorf("ip %s error: %v", strings.Join(args, " "), err)
	}
	return err
}

// DelRoute ...
func DelRoute(ip string) error {
	err := runCmd("ip", "route", "del", ip)
	if err != nil {
		err = fmt.Errorf("ip route del %s error: %v", ip, err)
	}
	return err
}

// SetupNAT ...
func SetupNAT(src string) (cancel func(), err error) {
	// TODO 考虑是否需要增加 "-o ! name" 来排除掉往 tun iface 中发的包
	err = runCmd("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", src, "-j", "MASQUERADE")
	if err != nil {
		return nil, fmt.Errorf("iptables error: %v", err)
	}
	return func() {
		runCmd("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", src, "-j", "MASQUERADE")
	}, nil
}

// RedirectDefaultGateway 参考 https://www.tinc-vpn.org/examples/redirect-gateway/
func RedirectDefaultGateway(dev string, devCIDR string, srvIP string) (reset func(), err error) {
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
