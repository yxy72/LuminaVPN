//go:build windows

package main

import (
	"encoding/binary"
	"testing"
)

func TestFixtureHandshakeAndScope(t *testing.T) {
	b := make([]byte, 40)
	b[0] = 0x45
	b[9] = 6
	binary.BigEndian.PutUint16(b[2:], 40)
	copy(b[12:20], []byte{192, 0, 2, 1, 192, 0, 2, 2})
	binary.BigEndian.PutUint16(b[20:], 30001)
	binary.BigEndian.PutUint16(b[22:], 18443)
	binary.BigEndian.PutUint32(b[24:], 99)
	b[32] = 0x50
	b[33] = 2
	key, r := fixturePacket(b)
	if key != "tcp_18443" || len(r) != 40 || r[33] != 0x12 || binary.BigEndian.Uint32(r[28:]) != 100 {
		t.Fatal("invalid SYNACK")
	}
	if checksum(r[:20]) != 0 {
		t.Fatal("invalid IPv4 checksum")
	}
	p := append([]byte(nil), r[12:20]...)
	p = append(p, 0, 6, 0, 20)
	p = append(p, r[20:]...)
	if checksum(p) != 0 {
		t.Fatal("invalid TCP checksum")
	}
	for _, change := range []func([]byte){func(x []byte) { x[19] = 3 }, func(x []byte) { x[6] = 0x20 }, func(x []byte) { x[32] = 0xf0 }, func(x []byte) { x[22] = 0 }, func(x []byte) { x[2] = 1 }} {
		bad := append([]byte(nil), b...)
		change(bad)
		if k, r := fixturePacket(bad); k != "" || r != nil {
			t.Fatal("out-of-scope packet accepted")
		}
	}
}

func TestFixtureUDPEchoIsBounded(t *testing.T) {
	b := make([]byte, 33)
	b[0] = 0x45
	b[9] = 17
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	copy(b[12:20], []byte{192, 0, 2, 1, 192, 0, 2, 2})
	binary.BigEndian.PutUint16(b[20:], 30001)
	binary.BigEndian.PutUint16(b[22:], 18444)
	binary.BigEndian.PutUint16(b[24:], 13)
	copy(b[28:], "probe")
	key, r := fixturePacket(b)
	if key != "udp" || len(r) != 33 || checksum(r[:20]) != 0 || string(r[28:]) != "probe" || binary.BigEndian.Uint16(r[20:]) != 18444 || binary.BigEndian.Uint16(r[22:]) != 30001 {
		t.Fatal("invalid echo")
	}
	for _, length := range []uint16{0, 7, 14, 65, 65535} {
		bad := append([]byte(nil), b...)
		binary.BigEndian.PutUint16(bad[24:], length)
		if k, r := fixturePacket(bad); k != "" || r != nil {
			t.Fatal("invalid UDP length admitted", length)
		}
	}
}
