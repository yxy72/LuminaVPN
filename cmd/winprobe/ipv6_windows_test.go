//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestIPv6FixtureScopeAndHandshake(t *testing.T) {
	b := make([]byte, 60)
	b[0], b[6], b[7] = 0x60, 6, 64
	binary.BigEndian.PutUint16(b[4:6], 20)
	copy(b[8:24], net.ParseIP("fe80::1234").To16())
	copy(b[24:40], net.ParseIP("fe80::2").To16())
	binary.BigEndian.PutUint16(b[40:42], 30001)
	binary.BigEndian.PutUint16(b[42:44], 18446)
	binary.BigEndian.PutUint32(b[44:48], 99)
	b[52], b[53] = 0x50, 2
	k, r := fixturePacket(b)
	if k != "tcp6_18446" || len(r) != 60 || r[53] != 0x12 || binary.BigEndian.Uint32(r[48:52]) != 100 || !bytes.Equal(r[8:24], b[24:40]) || !bytes.Equal(r[24:40], b[8:24]) || binary.BigEndian.Uint16(r[40:42]) != 18446 || binary.BigEndian.Uint16(r[42:44]) != 30001 {
		t.Fatal("invalid IPv6 handshake reply")
	}
	pseudo := append([]byte(nil), r[8:40]...)
	pseudo = append(pseudo, 0, 0, 0, 20, 0, 0, 0, 6)
	pseudo = append(pseudo, r[40:]...)
	if checksum(pseudo) != 0 {
		t.Fatal("invalid TCP6 checksum")
	}
	for _, change := range []func([]byte){
		func(x []byte) { x[6] = 44 }, // No fragments or extension headers.
		func(x []byte) { x[39] = 3 },
		func(x []byte) { x[8] = 0x20 },
		func(x []byte) { x[4] = 1 },
		func(x []byte) { x[5] = 19 },
		func(x []byte) { x[52] = 0xf0 },
		func(x []byte) { x[53] = 0x12 },
		func(x []byte) { x[43]++ },
	} {
		bad := append([]byte(nil), b...)
		change(bad)
		if k, r := fixturePacket(bad); k != "" || r != nil {
			t.Fatal("out-of-scope IPv6 packet accepted")
		}
	}
	for i := 0; i < len(b); i++ {
		if k, r := fixturePacket(b[:i]); k != "" || r != nil {
			t.Fatal("truncated IPv6 packet accepted")
		}
	}
}
