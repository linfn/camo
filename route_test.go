package camo

import (
	"runtime"
	"testing"
)

func newRouteTestIface() (iface *Iface, err error) {
	iface, err = NewTunIface(DefaultMTU)
	if err != nil {
		return nil, err
	}
	err = iface.SetIPv4("10.20.30.42/24")
	if err != nil {
		iface.Close()
		return nil, err
	}
	err = iface.SetIPv6("fd00:cafe:1234::2/64")
	if err != nil {
		iface.Close()
		return nil, err
	}
	return iface, nil
}

func TestRoute(t *testing.T) {
	iface, err := newRouteTestIface()
	if err != nil {
		t.Fatal(err)
	}
	defer iface.Close()

	type args struct {
		dst           string
		routeDst      string
		gateway       string
		darwinGateway string
		dev           string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			"IPv4", args{
				"10.20.31.0/24",
				"10.20.31.1",
				"10.20.30.41",
				"10.20.30.42",
				iface.Name(),
			},
		},
		{
			"IPv6", args{
				"fd00:cafe:1235::/64",
				"fd00:cafe:1235::1",
				"fd00:cafe:1234::1",
				"fd00:cafe:1234::1",
				iface.Name(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gateway := tt.args.gateway
			if runtime.GOOS == "darwin" {
				gateway = tt.args.darwinGateway
			}
			needClean := true

			err := AddRoute(tt.args.dst, gateway, tt.args.dev)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if needClean {
					_ = DelRoute(tt.args.dst, gateway, tt.args.dev)
				}
			}()

			gw, dev, err := GetRoute(tt.args.routeDst)
			if err != nil {
				t.Fatal(err)
			}
			if gw != gateway {
				t.Errorf("gw = %s, want %s", gw, gateway)
			}
			if dev != tt.args.dev {
				t.Errorf("dev = %s, want %s", dev, tt.args.dev)
			}

			needClean = false
			err = DelRoute(tt.args.dst, gateway, tt.args.dev)
			if err != nil {
				t.Fatal(err)
			}
			gw, dev, err = GetRoute(tt.args.routeDst)
			if err != nil {
				t.Fatal(err)
			}
			if gw == gateway {
				t.Errorf("gw = %s, want != %s", gw, gateway)
			}
			if dev == tt.args.dev {
				t.Errorf("dev = %s, want != %s", dev, tt.args.dev)
			}
		})
	}
}

func TestRedirectGateway(t *testing.T) {
	iface, err := newRouteTestIface()
	if err != nil {
		t.Fatal(err)
	}
	defer iface.Close()

	type args struct {
		dev           string
		gateway       string
		darwinGateway string
		dst           string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			"IPv4", args{
				iface.Name(),
				"10.20.30.41",
				"10.20.30.42",
				"8.8.8.8",
			},
		},
		{
			"IPv6", args{
				iface.Name(),
				"fd00:cafe:1234::1",
				"fd00:cafe:1234::1",
				"2001:4860:4860::8888",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gateway := tt.args.gateway
			if runtime.GOOS == "darwin" {
				gateway = tt.args.darwinGateway
			}
			reset, err := RedirectGateway(tt.args.dev, gateway)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				err := reset()
				if err != nil {
					t.Error(err)
				}
			}()

			gw, dev, err := GetRoute(tt.args.dst)
			if err != nil {
				t.Fatal(err)
			}
			if gw != gateway {
				t.Errorf("gw = %s, want %s", gw, gateway)
			}
			if dev != tt.args.dev {
				t.Errorf("dev = %s, want %s", dev, tt.args.dev)
			}
		})
	}
}
