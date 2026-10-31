//go:build windows

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"netlaunch/internal/securefile"
	"path/filepath"
	"unsafe"
)

func checksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}

// fixturePacket handles only our documentation-address TCP handshakes. It
// never forwards packets, resolves domains, or records application payloads.
func fixturePacket(b []byte) (string, []byte) {
	if len(b) > 0 && b[0]>>4 == 6 {
		return fixtureIPv6(b)
	}
	if len(b) < 20 || b[0]>>4 != 4 {
		return "", nil
	}
	i := int(b[0]&15) * 4
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if i < 20 || n > len(b) || n < i+8 || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
		return "", nil
	}
	if (string(b[12:16]) != string([]byte{192, 0, 2, 1}) && string(b[12:16]) != string([]byte{192, 0, 2, 3})) || string(b[16:20]) != string([]byte{192, 0, 2, 2}) {
		return "", nil
	}
	port := binary.BigEndian.Uint16(b[i+2 : i+4])
	if b[9] == 17 && port == 18444 {
		length := int(binary.BigEndian.Uint16(b[i+4 : i+6]))
		if length < 8 || length > 64 || i+length > n {
			return "", nil
		}
		r := make([]byte, 20+length)
		r[0] = 0x45
		r[8] = 64
		r[9] = 17
		binary.BigEndian.PutUint16(r[2:], uint16(len(r)))
		copy(r[12:16], b[16:20])
		copy(r[16:20], b[12:16])
		copy(r[20:22], b[i+2:i+4])
		copy(r[22:24], b[i:i+2])
		binary.BigEndian.PutUint16(r[24:], uint16(length))
		copy(r[28:], b[i+8:i+length])
		binary.BigEndian.PutUint16(r[10:], checksum(r[:20]))
		return "udp", r
	}
	if b[9] != 6 || n < i+20 || (port != 18443 && port != 18445) {
		return "", nil
	}
	tcp := b[i:n]
	if int(tcp[12]>>4)*4 < 20 || int(tcp[12]>>4)*4 > len(tcp) || tcp[13]&2 == 0 {
		return "", nil
	}
	r := make([]byte, 40)
	r[0] = 0x45
	r[8] = 64
	r[9] = 6
	binary.BigEndian.PutUint16(r[2:], 40)
	copy(r[12:16], b[16:20])
	copy(r[16:20], b[12:16])
	copy(r[20:22], tcp[2:4])
	copy(r[22:24], tcp[0:2])
	binary.BigEndian.PutUint32(r[24:], 12345)
	binary.BigEndian.PutUint32(r[28:], binary.BigEndian.Uint32(tcp[4:8])+1)
	r[32] = 0x50
	r[33] = 0x12
	binary.BigEndian.PutUint16(r[34:], 65535)
	pseudo := append([]byte(nil), r[12:20]...)
	pseudo = append(pseudo, 0, 6, 0, 20)
	pseudo = append(pseudo, r[20:]...)
	binary.BigEndian.PutUint16(r[36:], checksum(pseudo))
	binary.BigEndian.PutUint16(r[10:], checksum(r[:20]))
	return fmt.Sprintf("tcp_%d", port), r
}

type packetPump struct {
	receive, release, allocate, send *windows.Proc
	session                          uintptr
	counts                           map[string]int
}

func newPump(dll *windows.DLL, session uintptr) (*packetPump, error) {
	p := &packetPump{session: session, counts: map[string]int{}}
	for name, target := range map[string]**windows.Proc{"WintunReceivePacket": &p.receive, "WintunReleaseReceivePacket": &p.release, "WintunAllocateSendPacket": &p.allocate, "WintunSendPacket": &p.send} {
		v, e := dll.FindProc(name)
		if e != nil {
			return nil, e
		}
		*target = v
	}
	return p, nil
}
func (p *packetPump) drain(files securefile.AdminStore, id, role string) error {
	changed := false
	for i := 0; i < 128; i++ {
		var size uint32
		ptr, _, e := p.receive.Call(p.session, uintptr(unsafe.Pointer(&size)))
		if ptr == 0 {
			if errors.Is(e, windows.ERROR_NO_MORE_ITEMS) {
				break
			}
			return e
		}
		if size > 65535 {
			p.release.Call(p.session, ptr)
			return errors.New("invalid Wintun packet length")
		}
		view := unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&ptr))), size)
		key, reply := fixturePacket(view)
		p.release.Call(p.session, ptr)
		if key != "" {
			p.counts[key]++
			changed = true
		}
		if reply != nil {
			out, _, err := p.allocate.Call(p.session, uintptr(len(reply)))
			if out == 0 {
				return err
			}
			copy(unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&out))), len(reply)), reply)
			p.send.Call(p.session, out)
		}
	}
	if changed {
		return files.Write(filepath.Join(id, "probe-packets"+role+".json"), p.counts)
	}
	return nil
}
