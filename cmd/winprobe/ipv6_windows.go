//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"netlaunch/internal/winnet"
	"strconv"
	"time"
)

var fixtureIPv6Peer = net.ParseIP("fe80::2").To16()

// Only a link-local TCP SYN to our fixture port is answered. No routing,
// address advertisement, or changes to the host's IPv6 configuration occur.
// The TCP pseudo-header follows RFC 8200 section 8.1.
func fixtureIPv6(b []byte) (string, []byte) {
	if len(b) < 60 || b[0]>>4 != 6 || b[6] != 6 {
		return "", nil
	}
	n := 40 + int(binary.BigEndian.Uint16(b[4:6]))
	if n < 60 || n > len(b) || !net.IP(b[8:24]).IsLinkLocalUnicast() || !bytes.Equal(b[24:40], fixtureIPv6Peer) {
		return "", nil
	}
	tcp := b[40:n]
	if binary.BigEndian.Uint16(tcp[2:4]) != 18446 || tcp[13] != 2 || int(tcp[12]>>4)*4 < 20 || int(tcp[12]>>4)*4 > len(tcp) {
		return "", nil
	}
	r := make([]byte, 60)
	r[0], r[6], r[7] = 0x60, 6, 64
	binary.BigEndian.PutUint16(r[4:6], 20)
	copy(r[8:24], b[24:40])
	copy(r[24:40], b[8:24])
	copy(r[40:42], tcp[2:4])
	copy(r[42:44], tcp[:2])
	binary.BigEndian.PutUint32(r[44:48], 12345)
	binary.BigEndian.PutUint32(r[48:52], binary.BigEndian.Uint32(tcp[4:8])+1)
	r[52], r[53] = 0x50, 0x12
	binary.BigEndian.PutUint16(r[54:56], 65535)
	pseudo := append([]byte(nil), r[8:40]...)
	pseudo = append(pseudo, 0, 0, 0, 20, 0, 0, 0, 6)
	pseudo = append(pseudo, r[40:]...)
	binary.BigEndian.PutUint16(r[56:58], checksum(pseudo))
	return "tcp6_18446", r
}

func ipv6Probe(a winnet.Adapter) error {
	// Validate the captured adapter identity before using its interface index.
	if e := winnet.ValidateAdapter(a, "192.0.2.1"); e != nil {
		return e
	}
	iface, e := net.InterfaceByIndex(int(a.Index))
	if e != nil {
		return e
	}
	addresses, e := iface.Addrs()
	if e != nil {
		return e
	}
	var source net.IP
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.To4() == nil && ip.IsLinkLocalUnicast() {
			source = ip
			break
		}
	}
	if source == nil {
		return errors.New("owned adapter has no IPv6 link-local address")
	}
	zone := strconv.FormatUint(uint64(a.Index), 10)
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: source, Zone: zone}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, e := d.DialContext(ctx, "tcp6", "[fe80::2%"+zone+"]:18446")
	if e == nil {
		c.Close()
	}
	return e
}
