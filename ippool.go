package camo

import (
	"math"
	"net"
	"sync"
)

// IPPool assigns ip addresses
type IPPool interface {
	Get() (net.IP, bool)
	Use(net.IP) bool
	Free(net.IP)
}

// SubnetIPPool assigns ip addresses in a subnet segment.
// Currently supports up to 256 allocations.
type SubnetIPPool struct {
	subnet *net.IPNet
	bitmap []bool
	i      int
	mu     sync.Mutex
}

func iptoi(ip net.IP, subnet *net.IPNet) int {
	if !subnet.Contains(ip) {
		return -1
	}
	return int(ip[len(ip)-1] - subnet.IP[len(subnet.IP)-1])
}

func itoip(i int, subnet *net.IPNet) net.IP {
	ip := make(net.IP, len(subnet.IP))
	copy(ip, subnet.IP)
	ip[len(ip)-1] += byte(i)
	return ip
}

// NewSubnetIPPool ...
func NewSubnetIPPool(subnet *net.IPNet, limit int) *SubnetIPPool {
	ones, bits := subnet.Mask.Size()
	x := bits - ones
	if x > 8 {
		x = 8
	}
	size := int(math.Exp2(float64(x)))
	if limit > 0 && size > limit {
		size = limit
	}
	p := &SubnetIPPool{
		subnet: subnet,
		bitmap: make([]bool, size),
	}
	if subnet.IP.To4() != nil {
		p.bitmap[0] = true
		last := itoip(size-1, subnet)
		if last[len(last)-1] == 255 {
			p.bitmap[size-1] = true
		}
	}
	return p
}

// Get ...
func (p *SubnetIPPool) Get() (net.IP, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	size := len(p.bitmap)
	for j := 0; j < size; j++ {
		p.i = (p.i + 1) % size
		if !p.bitmap[p.i] {
			p.bitmap[p.i] = true
			return itoip(p.i, p.subnet), true
		}
	}
	return nil, false
}

// Use ...
func (p *SubnetIPPool) Use(ip net.IP) bool {
	i := iptoi(ip, p.subnet)
	if i < 0 || i >= len(p.bitmap) {
		return false
	}
	p.mu.Lock()
	p.bitmap[i] = true
	p.mu.Unlock()
	return true
}

// Free ...
func (p *SubnetIPPool) Free(ip net.IP) {
	i := iptoi(ip, p.subnet)
	if i < 0 || i >= len(p.bitmap) {
		return
	}
	p.mu.Lock()
	p.bitmap[i] = false
	p.mu.Unlock()
}
