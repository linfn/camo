package camo

import (
	"net"
	"testing"
)

func TestNewTunIface(t *testing.T) {
	const mtu = 1400

	iface, err := NewTunIface(mtu)
	if err != nil {
		t.Fatal(err)
	}
	defer iface.Close()

	netIface, err := net.InterfaceByName(iface.Name())
	if err != nil {
		t.Fatal(err)
	}

	if netIface.MTU != mtu {
		t.Errorf("mtu = %d, want %v", netIface.MTU, mtu)
	}
}

func TestIface_SetIP(t *testing.T) {
	iface, err := NewTunIface(DefaultMTU)
	if err != nil {
		t.Fatal(err)
	}
	defer iface.Close()

	type args struct {
		cidrs     []string
		setIP     func(cidr string) error
		getCIDR   func() string
		getIP     func() net.IP
		getSubnet func() *net.IPNet
	}
	tests := []struct {
		name string
		args args
	}{
		{"IPv4", args{
			[]string{"10.20.30.40/24", "10.20.30.41/24"},
			iface.SetIPv4,
			iface.CIDR4,
			iface.IPv4,
			iface.Subnet4,
		}},
		{"IPv6", args{
			[]string{"fd00:cafe:1234::1/64", "fd00:cafe:1234::2/64"},
			iface.SetIPv6,
			iface.CIDR6,
			iface.IPv6,
			iface.Subnet6,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, cidr := range tt.args.cidrs {
				ip, subnet, err := net.ParseCIDR(cidr)
				if err != nil {
					t.Fatal(err)
				}

				err = tt.args.setIP(cidr)
				if err != nil {
					t.Fatal(err)
				}

				if cidr != tt.args.getCIDR() {
					t.Errorf("tt.args.getCIDR() = %s, want %s", tt.args.getCIDR(), cidr)
				}
				if !ip.Equal(tt.args.getIP()) {
					t.Errorf("tt.args.getIP() = %s, want %s", tt.args.getIP(), ip)
				}
				if subnet.String() != tt.args.getSubnet().String() {
					t.Errorf("tt.args.getSubnet() = %s, want %s", tt.args.getSubnet(), subnet)
				}
			}

			err = tt.args.setIP("")
			if err != nil {
				t.Fatal(err)
			}
			if tt.args.getCIDR() != "" {
				t.Errorf("tt.args.getCIDR() = %s, want \"\"", tt.args.getCIDR())
			}
			if tt.args.getIP() != nil {
				t.Errorf("tt.args.getIP() = %s, want nil", tt.args.getIP())
			}
			if tt.args.getSubnet() != nil {
				t.Errorf("tt.args.getSubnet() = %s, want nil", tt.args.getSubnet())
			}
		})
	}
}
