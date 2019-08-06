package camo

import (
	"net"
)

// IPPool ...
type IPPool struct {
	subnet *net.IPNet
	bitmap []byte
	bits   int
	i      int
}

// NewIPPool ...
func NewIPPool(subnet *net.IPNet) *IPPool {
	ones, bits := subnet.Mask.Size()
	size := bits - ones
	if size > 8 {
		size = 8
	}
	bitmap := make([]byte, (size+7)/8)
	return &IPPool{
		subnet: subnet,
		bitmap: bitmap,
		bits:   size,
	}
}

// Get TODO
func (p *IPPool) Get() (net.IP, bool) {
	p.i++
	ip := make(net.IP, len(p.subnet.IP))
	copy(ip, p.subnet.IP)
	ip[len(p.subnet.IP)-1] += byte(p.i)
	return ip, true
}

// Free TODO
func (p *IPPool) Free(net.IP) {
}
