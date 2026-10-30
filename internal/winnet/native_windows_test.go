//go:build windows

package winnet

import (
	"net"
	"testing"
)

func TestNativeReadOnly(t *testing.T) {
	a, e := Adapters()
	if e != nil {
		t.Fatal(e)
	}
	r, e := Routes()
	if e != nil {
		t.Fatal(e)
	}
	if len(a) == 0 || len(r) == 0 {
		t.Fatal("empty native network snapshot")
	}
	for _, dev := range a {
		if dev.Index == 0 || !dev.Hardware || !dev.Up || (dev.Type != 6 && dev.Type != 71) {
			continue
		}
		iface, e := net.InterfaceByIndex(int(dev.Index))
		if e != nil {
			t.Fatal(e)
		}
		if iface.Name != dev.Name {
			t.Fatal("interface alias differs")
		}
	}
	n, e := SelectPhysical(a, r)
	if e != nil {
		t.Skip("physical discovery unavailable:", e)
	}
	if e = ValidateAdapter(n.Adapter, n.Address); e != nil {
		t.Fatal(e)
	}
	stale := n.Adapter
	stale.LUID++
	if e = ValidateAdapter(stale, n.Address); e == nil {
		t.Fatal("reused index accepted")
	}
	t.Logf("physical exit validated; adapters=%d routes=%d", len(a), len(r))
}

func TestNativeRouteEncodingWithoutMutation(t *testing.T) {
	r, e := NewRoute(Adapter{Index: 7, LUID: 123}, "192.0.2.1/32", "0.0.0.0", 317)
	if e != nil {
		t.Fatal(e)
	}
	row, e := nativeRow(r)
	if e != nil {
		t.Fatal(e)
	}
	got, e := routeFromRow(row)
	if e != nil || got != r {
		t.Fatal("native encoding changed attributes", got, e)
	}
	if _, e = Lookup(Route{}); e == nil {
		t.Fatal("invalid route lookup accepted")
	}
}

func TestLookupAbsentWithRemovedAdapter(t *testing.T) {
	r, e := NewRoute(Adapter{Index: ^uint32(0), LUID: ^uint64(0)}, "192.0.2.245/32", "0.0.0.0", 317)
	if e != nil {
		t.Fatal(e)
	}
	actual, e := Lookup(r)
	if e != nil || actual != nil {
		t.Fatal("cannot prove route absence after adapter removal", e)
	}
}
