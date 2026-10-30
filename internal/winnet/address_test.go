package winnet

import "testing"

func TestVPNAddressScope(t *testing.T) {
	adapter := Adapter{Index: 7, LUID: 77, GUID: "test", Type: 53}
	a, e := NewVPNAddress(adapter, "192.0.2.8")
	if e != nil {
		t.Fatal(e)
	}
	b := a
	b.Created = 1
	if !OwnedAddressEqual(a, b) {
		t.Fatal("planned creation not matched")
	}
	a.Created = 2
	if OwnedAddressEqual(a, b) {
		t.Fatal("different kernel creation matched")
	}
	for _, ip := range []string{"127.0.0.1", "0.0.0.0", "169.254.1.2", "224.0.0.1", "::1"} {
		if _, e := NewVPNAddress(adapter, ip); e == nil {
			t.Fatalf("invalid address accepted: %s", ip)
		}
	}
	a.Created = 0
	a.PrefixLength = 24
	if a.Validate() == nil {
		t.Fatal("server subnet accepted")
	}
	adapter.Hardware = true
	if _, e := NewVPNAddress(adapter, "192.0.2.8"); e == nil {
		t.Fatal("physical adapter accepted")
	}
}
