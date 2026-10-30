package winnet

import "testing"

func TestPhysicalSelectionExcludesTunnelAndUsesTotalMetric(t *testing.T) {
	a := []Adapter{
		{Index: 1, LUID: 11, Name: "TUN", Up: true, Type: 6, Addresses: []string{"198.18.0.1"}},
		{Index: 2, LUID: 22, Name: "Wi-Fi", Up: true, Hardware: true, Type: 71, Metric: 20, Addresses: []string{"192.168.1.10"}},
		{Index: 3, LUID: 33, Name: "Ethernet", Up: true, Hardware: true, Type: 6, Metric: 10, Addresses: []string{"10.0.0.10"}},
	}
	r := []Route{{InterfaceIndex: 1, InterfaceLUID: 11, Prefix: "0.0.0.0/0", NextHop: "198.18.0.2"}, {InterfaceIndex: 2, InterfaceLUID: 22, Prefix: "0.0.0.0/0", NextHop: "192.168.1.1", Metric: 5}, {InterfaceIndex: 3, InterfaceLUID: 33, Prefix: "0.0.0.0/0", NextHop: "10.0.0.1", Metric: 100}}
	n, e := SelectPhysical(a, r)
	if e != nil || n.Adapter.Index != 2 {
		t.Fatal(n, e)
	}
	r[1].InterfaceLUID = 99
	n, e = SelectPhysical(a, r)
	if e != nil || n.Adapter.Index != 3 {
		t.Fatal("reused index", n, e)
	}
	r[1].InterfaceLUID = 22
	r[2].Metric = 15
	if _, e = SelectPhysical(a, r); e == nil {
		t.Fatal("ambiguous exit accepted")
	}
	a[1].Addresses = []string{"169.254.1.1"}
	a[2].Up = false
	if _, e = SelectPhysical(a, r); e == nil {
		t.Fatal("unavailable exits accepted")
	}
}

func TestManagedRouteOwnership(t *testing.T) {
	r, e := NewRoute(Adapter{Index: 2, LUID: 22}, "192.0.2.1/32", "0.0.0.0", 317)
	if e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Route){func(r *Route) { r.InterfaceLUID++ }, func(r *Route) { r.Metric++ }, func(r *Route) { r.Protocol++ }, func(r *Route) { r.Publish = true }, func(r *Route) { r.ValidLifetime-- }} {
		b := r
		mutate(&b)
		if OwnedEqual(r, b) {
			t.Fatal("changed route accepted")
		}
	}
	for _, p := range []string{"0.0.0.0/0", "192.0.2.1/24", "::/0", "224.0.0.1/32", "127.0.0.1/32"} {
		if _, e := NewRoute(Adapter{Index: 2, LUID: 22}, p, "0.0.0.0", 317); e == nil {
			t.Fatal("unsafe route", p)
		}
	}
}

func TestCaptureRoutesRequireVirtualAdapter(t *testing.T) {
	a := Adapter{Index: 7, LUID: 77, GUID: "candidate", Type: 53}
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		r, e := NewCaptureRoute(a, prefix)
		if e != nil || r.Validate() != nil {
			t.Fatal("invalid capture half", e)
		}
	}
	a.Hardware = true
	if _, e := NewCaptureRoute(a, "0.0.0.0/1"); e == nil {
		t.Fatal("physical capture accepted")
	}
	a.Hardware = false
	if _, e := NewCaptureRoute(a, "0.0.0.0/0"); e == nil {
		t.Fatal("physical default replacement accepted")
	}
}
