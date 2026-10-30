//go:build windows

package winnet

import (
	"testing"
	"unsafe"
)

func TestConfiguredDNSReadOnly(t *testing.T) {
	if unsafe.Sizeof(dnsInterfaceSettings{}) != 64 || unsafe.Offsetof(dnsInterfaceSettings{}.NameServer) != 24 {
		t.Fatal("DNS ABI layout mismatch")
	}
	p, e := Discover()
	if e != nil {
		t.Skip("physical network unavailable:", e)
	}
	a, e := ConfiguredDNS(p.Adapter)
	if e != nil {
		t.Fatal(e)
	}
	b, e := ConfiguredDNS(p.Adapter)
	if e != nil {
		t.Fatal(e)
	}
	if !SameDNS(a, b) {
		t.Fatal("DNS changed during readonly snapshot")
	}
	t.Logf("configured DNS: automatic=%t profile_override=%t", a.NameServers == "", a.ProfileNameServers != "")
}
