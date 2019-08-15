package camo

import (
	"net"
	"testing"
)

func TestSubnetIPPool(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.20.0.10/24")
	ippool := NewSubnetIPPool(subnet, 0)
	ippool.Use(net.ParseIP("10.20.0.10"), "")
	ips := map[string]net.IP{}
	for {
		ip, ok := ippool.Get("")
		if !ok {
			break
		}
		ips[ip.String()] = ip
	}
	if len(ips) != 253 {
		t.Fail()
	}
	if _, ok := ips["10.20.0.10"]; ok {
		t.Fail()
	}

	for _, v := range ips {
		ippool.Free(v)
	}
	ips = map[string]net.IP{}
	for {
		ip, ok := ippool.Get("")
		if !ok {
			break
		}
		ips[ip.String()] = ip
	}
	if len(ips) != 253 {
		t.Fail()
	}

	if ippool.Use(net.ParseIP("10.30.0.10"), "") {
		t.Fail()
	}
	ippool.Free(net.ParseIP("10.30.0.10"))
}
