package camo

import (
	"errors"
	"io"

	"golang.org/x/net/ipv4"
)

// DefaultMTU = 1500 - 20(ip header) - 20(tcp header) - 9(http2 frame header)
// TODO DefaultMTU
const DefaultMTU = 1500

var (
	errBadPacketRead            = errors.New("bad packet read")
	errPacketTooLarge           = errors.New("packet too large")
	errUnsupportedPacketVersion = errors.New("unsupported packet version")
)

func readPacket(b []byte, h *ipv4.Header, r io.Reader) (int, error) {
	if len(b) < ipv4.HeaderLen {
		return 0, io.ErrShortBuffer
	}
	_, err := io.ReadFull(r, b[:ipv4.HeaderLen])
	if err != nil {
		return 0, err
	}
	err = h.Parse(b[:ipv4.HeaderLen])
	if err != nil {
		return 0, err
	}
	if h.Version != 4 {
		return 0, errUnsupportedPacketVersion
	}
	if h.TotalLen > len(b) {
		return 0, io.ErrShortBuffer
	} else if h.TotalLen < ipv4.HeaderLen {
		return 0, errBadPacketRead
	}
	_, err = io.ReadFull(r, b[ipv4.HeaderLen:h.TotalLen])
	if err != nil {
		return 0, err
	}
	return h.TotalLen, nil
}

func writePacket(w io.Writer, b []byte) (int, error) {
	return w.Write(b)
}
