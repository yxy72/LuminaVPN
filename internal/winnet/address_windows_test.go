//go:build windows

package winnet

import (
	"golang.org/x/sys/windows"
	"testing"
)

func TestNativeVPNAddressEncoding(t *testing.T) {
	a, e := NewVPNAddress(Adapter{Index: 7, LUID: 77, GUID: "test", Type: 53}, "192.0.2.8")
	if e != nil {
		t.Fatal(e)
	}
	row, e := nativeUnicast(a)
	if e != nil {
		t.Fatal(e)
	}
	if row.DadState == windows.IpDadStatePreferred {
		t.Fatal("optimistic DAD enabled")
	}
	got, e := addressFromRow(row)
	if e != nil || !SameAddressAttributes(a, got) {
		t.Fatal("native address roundtrip", e)
	}
}
func TestNativeAddressAndMTUReadOnly(t *testing.T) {
	all, e := Addresses()
	if e != nil {
		t.Fatal(e)
	}
	if len(all) == 0 {
		t.Fatal("empty address table")
	}
	physical, e := Discover()
	if e != nil {
		t.Fatal(e)
	}
	mtu, e := MTU(physical.Adapter)
	if e != nil || mtu < 576 {
		t.Fatal("native MTU read", e)
	}
	// Table lookup also proves absence after Windows removes an old adapter.
	a, e := NewVPNAddress(Adapter{Index: ^uint32(0), LUID: ^uint64(0), GUID: "absent", Type: 53}, "192.0.2.247")
	if e != nil {
		t.Fatal(e)
	}
	found, e := LookupAddress(a)
	if e != nil || found != nil {
		t.Fatal("removed adapter address lookup", e)
	}
	t.Logf("native IPv4 addresses=%d physical MTU=%d; no changes made", len(all), mtu)
}
