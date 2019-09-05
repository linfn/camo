package camo

import (
	"fmt"
	"net"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/songgao/water"
)

func createTun() (*water.Interface, error) {
	return water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			ComponentID: "tap0901",
			Network:     "10.20.0.2/24",
		},
	})
}

func getfd(ifce *water.Interface) syscall.Handle {
	return *(*syscall.Handle)(unsafe.Pointer(reflect.ValueOf(ifce.ReadWriteCloser).Elem().FieldByName("fd").UnsafeAddr()))
}

var (
	tapIoCtlConfigTun = tapControlCode(10, 0)
	fileDeviceUnknown = uint32(0x00000022)
)

func ctlCode(deviceType, function, method, access uint32) uint32 {
	return (deviceType << 16) | (access << 14) | (function << 2) | method
}
func tapControlCode(request, method uint32) uint32 {
	return ctlCode(fileDeviceUnknown, request, method, 0)
}

func windowsTUNControlIP4(ifce *water.Interface, cidr string) error {
	fd := getfd(ifce)
	var bytesReturned uint32
	rdbbuf := make([]byte, syscall.MAXIMUM_REPARSE_DATA_BUFFER_SIZE)

	localIP, remoteNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("failed to parse cidr: %v", err)
	}
	if localIP.To4() == nil {
		return fmt.Errorf("provided cidr(%s) is not a valid IPv4 address", cidr)
	}
	code2 := make([]byte, 0, 12)
	code2 = append(code2, localIP.To4()[:4]...)
	code2 = append(code2, remoteNet.IP.To4()[:4]...)
	code2 = append(code2, remoteNet.Mask[:4]...)
	if len(code2) != 12 {
		return fmt.Errorf("provided cidr(%s) is not valid", cidr)
	}
	if err := syscall.DeviceIoControl(fd, tapIoCtlConfigTun, &code2[0], uint32(12), &rdbbuf[0], uint32(len(rdbbuf)), &bytesReturned, nil); err != nil {
		return err
	}
	return nil
}
