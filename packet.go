package camo

import (
	"encoding/binary"
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

func parseIPv4Header(h *ipv4.Header, b []byte) error {
	err := h.Parse(b)
	if err != nil {
		return err
	}
	h.TotalLen = int(binary.BigEndian.Uint16(b[2:4]))
	h.FragOff = int(binary.BigEndian.Uint16(b[6:8]))
	return nil
}

func readPacket(b []byte, h *ipv4.Header, r io.Reader) (int, error) {
	if len(b) < ipv4.HeaderLen {
		return 0, io.ErrShortBuffer
	}
	_, err := io.ReadFull(r, b[:ipv4.HeaderLen])
	if err != nil {
		return 0, err
	}
	err = parseIPv4Header(h, b[:ipv4.HeaderLen])
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
