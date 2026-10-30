package engine

import (
	"netlaunch/internal/platform"
	"testing"
)

func TestCrashWindowPhysicalRoute(t *testing.T) {
	planned := OwnedRoute{Route: platform.Route{Prefix: "192.0.2.1/32", Gateway: "192.0.2.254", Interface: "en4"}, State: "planned", InterfaceIndex: 4}
	actual := planned.Route
	actual.Flags = "UGHS"
	if !ownedRouteMatches(planned, actual) {
		t.Fatal("post-add pre-journal crash cannot recover")
	}
	for _, mutate := range []func(*platform.Route){func(r *platform.Route) { r.Gateway = "192.0.2.253" }, func(r *platform.Route) { r.Interface = "en5" }, func(r *platform.Route) { r.Prefix = "192.0.2.2/32" }, func(r *platform.Route) { r.Scoped = true }, func(r *platform.Route) { r.Flags = "UGH" }} {
		r := actual
		mutate(&r)
		if ownedRouteMatches(planned, r) {
			t.Fatal("foreign route adopted")
		}
	}
}
func TestScopedRouteOwnership(t *testing.T) {
	r := platform.Route{Prefix: "10.1.2.3/32", Gateway: "utun33", Interface: "utun33", Scoped: true, Flags: "UHSI"}
	entry := OwnedRoute{r, "applied", 33}
	if !ownedRouteMatches(entry, r) {
		t.Fatal("own route rejected")
	}
	r.Gateway = "utun34"
	if ownedRouteMatches(entry, r) {
		t.Fatal("changed route deleted")
	}
	entry.State = "removed"
	if ownedRouteMatches(entry, entry.Route) {
		t.Fatal("removed journal reused")
	}
}
func TestDNSRecoveryPreservesExternalChanges(t *testing.T) {
	d := DNSChange{Before: []string{"192.0.2.53"}, After: []string{"127.0.0.1"}}
	restore, e := restoreDNS(d.After, d)
	if e != nil || !restore {
		t.Fatal(e)
	}
	restore, e = restoreDNS(d.Before, d)
	if e != nil || restore {
		t.Fatal("not idempotent")
	}
	if _, e = restoreDNS([]string{"1.1.1.1"}, d); e == nil {
		t.Fatal("overwrote outside change")
	}
	d.Before = []string{}
	if restore, e = restoreDNS(nil, d); e != nil || restore {
		t.Fatal("DHCP baseline")
	}
}
