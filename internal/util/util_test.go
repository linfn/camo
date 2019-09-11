package util

import (
	"net"
	"testing"
)

func TestRollback(t *testing.T) {
	var rollback Rollback

	var result int
	rollback.Add(func() { result++ })
	rollback.Add(func() { result++ })

	rollback.Do()
	if result != 2 {
		t.Error()
	}
}

func TestGetHostPortAddr(t *testing.T) {
	type args struct {
		addr        string
		defaultPort string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "host with port",
			args: args{"localhost:80", "443"},
			want: "localhost:80",
		},
		{
			name: "host without port",
			args: args{"localhost", "443"},
			want: "localhost:443",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetHostPortAddr(tt.args.addr, tt.args.defaultPort)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetHostPortAddr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetHostPortAddr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsIPv4(t *testing.T) {
	type args struct {
		ip string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "ipv4",
			args: args{"127.0.0.1"},
			want: true,
		},
		{
			name: "ipv4 cidr",
			args: args{"127.0.0.1/32"},
			want: true,
		},
		{
			name: "ipv6",
			args: args{"::1"},
			want: false,
		},
		{
			name: "ipv6 cidr",
			args: args{"::1/32"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsIPv4(tt.args.ip); got != tt.want {
				t.Errorf("IsIPv4() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToCIDR(t *testing.T) {
	type args struct {
		ip   net.IP
		mask net.IPMask
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "ipv4",
			args: args{net.ParseIP("127.0.0.1"), net.CIDRMask(24, 32)},
			want: "127.0.0.1/24",
		},
		{
			name: "ipv6",
			args: args{net.ParseIP("::1"), net.CIDRMask(64, 128)},
			want: "::1/64",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ToCIDR(tt.args.ip, tt.args.mask); got != tt.want {
				t.Errorf("ToCIDR() = %v, want %v", got, tt.want)
			}
		})
	}
}
