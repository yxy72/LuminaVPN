package platform

import (
	"net"
	"strings"
	"testing"
)

func TestPortChecksIdentifyOccupiedTransport(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	if e := CheckPort(l.Addr().(*net.TCPAddr).Port); e == nil || !strings.Contains(e.Error(), "TCP") {
		t.Fatal("TCP conflict lost", e)
	}
	u, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	if e := CheckPort(u.LocalAddr().(*net.UDPAddr).Port); e == nil || !strings.Contains(e.Error(), "UDP") {
		t.Fatal("UDP conflict lost", e)
	}
}
