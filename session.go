package camo

import (
	"net"
	"time"
)

// Session ...
type Session struct {
	cid       string
	ip        net.IP
	ttl       time.Duration
	writeChan chan []byte
}
