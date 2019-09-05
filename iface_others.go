// +build !windows

package camo

import "github.com/songgao/water"

func createTun() (*water.Interface, error) {
	return water.New(water.Config{DeviceType: water.TUN})
}

func windowsTUNControlIP4(ifce *water.Interface, cidr string) error {
	panic("not on windows")
}
