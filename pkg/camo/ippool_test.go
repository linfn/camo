package camo

import (
	"net"
	"testing"
)

func TestSubnetIPPool(t *testing.T) {
	gw, subnet, _ := net.ParseCIDR("10.20.0.1/24")
	ippool := NewSubnetIPPool(subnet, gw, 0)
	ips := map[string]net.IP{}
	for {
		ip, _, ok := ippool.Get("")
		if !ok {
			break
		}
		ips[ip.String()] = ip
	}
	if len(ips) != 253 {
		t.Error()
	}
	if _, ok := ips["10.20.0.1"]; ok {
		t.Error("can not assign the gateway's ip")
	}

	for _, v := range ips {
		ippool.Free(v)
	}
	ips = map[string]net.IP{}
	for {
		ip, _, ok := ippool.Get("")
		if !ok {
			break
		}
		ips[ip.String()] = ip
	}
	if len(ips) != 253 {
		t.Error()
	}

	if _, ok := ippool.Use(net.ParseIP("10.30.0.10"), ""); ok {
		t.Error()
	}
	ippool.Free(net.ParseIP("10.30.0.10"))
}
