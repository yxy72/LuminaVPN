package winstate

import (
	"errors"
	"fmt"
	"netlaunch/internal/winnet"
	"netlaunch/internal/winwfp"
	"testing"
)

type isolationNative struct {
	fakeNative
	adapters                    map[string]winnet.Adapter
	owned                       map[winnet.Route]winnet.Route
	guards                      map[string]winwfp.Status
	vpn, tun                    winnet.Adapter
	spec                        winwfp.Spec
	trace                       []string
	failVPNDelete, guardChanged bool
}

func routeKey(r winnet.Route) winnet.Route {
	return winnet.Route{InterfaceIndex: r.InterfaceIndex, InterfaceLUID: r.InterfaceLUID, Prefix: r.Prefix, NextHop: r.NextHop}
}
func (n *isolationNative) Adapter(id string) (winnet.Adapter, error) {
	a, ok := n.adapters[id]
	if !ok {
		return a, winnet.ErrAdapterAbsent
	}
	return a, nil
}
func (n *isolationNative) Lookup(r winnet.Route) (*winnet.Route, error) {
	v, ok := n.owned[routeKey(r)]
	if !ok {
		return nil, nil
	}
	return &v, nil
}
func (n *isolationNative) Add(r winnet.Route) (winnet.Route, error) {
	if _, ok := n.owned[routeKey(r)]; ok {
		return r, errors.New("already exists")
	}
	if !n.guards[n.spec.Sublayer].Complete() {
		return r, errors.New("invariant: adding route without guard")
	}
	role := "capture"
	if r.InterfaceLUID == n.vpn.LUID {
		role = "vpn"
		cap := r
		cap.InterfaceIndex = n.tun.Index
		cap.InterfaceLUID = n.tun.LUID
		if _, ok := n.owned[routeKey(cap)]; !ok {
			return r, errors.New("invariant: VPN before capture")
		}
	}
	n.trace = append(n.trace, "add-"+role)
	n.owned[routeKey(r)] = r
	return r, nil
}
func (n *isolationNative) Delete(r winnet.Route) error {
	role := "vpn"
	if r.InterfaceLUID == n.tun.LUID {
		role = "capture"
		vpn := r
		vpn.InterfaceIndex = n.vpn.Index
		vpn.InterfaceLUID = n.vpn.LUID
		if _, ok := n.owned[routeKey(vpn)]; ok {
			return errors.New("invariant: capture removed before VPN")
		}
	} else if n.failVPNDelete {
		return errors.New("injected VPN deletion failure")
	}
	n.trace = append(n.trace, "delete-"+role)
	delete(n.owned, routeKey(r))
	return nil
}
func (n *isolationNative) InspectGuard(s winwfp.Spec) (winwfp.Status, error) {
	if n.guardChanged {
		return winwfp.Status{}, errors.New("external guard edit")
	}
	return n.guards[s.Sublayer], nil
}
func (n *isolationNative) AddGuard(s winwfp.Spec) error {
	n.trace = append(n.trace, "guard-add")
	n.guards[s.Sublayer] = winwfp.Status{Sublayer: true, ForeignApp: true, NonTCP: true, IPv6: true}
	return nil
}
func (n *isolationNative) RemoveGuard(s winwfp.Spec) error {
	if len(n.owned) != 0 {
		return errors.New("invariant: guard removed before routes")
	}
	n.trace = append(n.trace, "guard-remove")
	delete(n.guards, s.Sublayer)
	return nil
}
func isolationFixture(t *testing.T) (Manager, *memoryStore, *isolationNative, winwfp.Spec) {
	t.Helper()
	m, store, base, _ := fixture(t)
	vpn := winnet.Adapter{Index: 9, LUID: 99, GUID: "vpn", Name: "VPN", Type: 53, Up: true, Metric: 10}
	tun := winnet.Adapter{Index: 8, LUID: 88, GUID: "tun", Name: "TUN", Type: 53, Up: true, Metric: 500}
	spec, e := winwfp.New(vpn, `C:\ProgramData\NetLaunch\run\netlaunch.exe`, []byte{1, 0, 0, 0})
	if e != nil {
		t.Fatal(e)
	}
	n := &isolationNative{fakeNative: *base, adapters: map[string]winnet.Adapter{vpn.GUID: vpn, tun.GUID: tun}, owned: map[winnet.Route]winnet.Route{}, guards: map[string]winwfp.Status{}, vpn: vpn, tun: tun, spec: spec}
	m.Native = n
	return m, store, n, spec
}
func installPair(t *testing.T, m Manager, n *isolationNative, spec winwfp.Spec) {
	t.Helper()
	if e := m.EnsureGuard(spec); e != nil {
		t.Fatal(e)
	}
	if e := m.EnsureCompanyRoute(spec, n.tun, "192.0.2.5/32"); e != nil {
		t.Fatal(e)
	}
}
func TestIsolationInstallAndRecoveryOrder(t *testing.T) {
	m, s, n, g := isolationFixture(t)
	installPair(t, m, n, g)
	if e := m.CheckCompanyAddress(g, "192.0.2.5"); e != nil {
		t.Fatal(e)
	}
	if e := m.CheckCompanyAddress(g, "192.0.2.6"); e == nil {
		t.Fatal("uncovered IP authorized")
	}
	j, _ := s.Load()
	p := j.Pairs[0]
	if uint64(n.tun.Metric)+uint64(p.Capture.Route.Metric) >= uint64(n.vpn.Metric)+uint64(p.VPN.Route.Metric) {
		t.Fatal("wrong effective metric")
	}
	if e := m.Recover(); e != nil {
		t.Fatal(e)
	}
	if got := fmt.Sprint(n.trace); got != "[guard-add add-capture add-vpn delete-vpn delete-capture guard-remove]" {
		t.Fatal(got)
	}
	if e := m.Recover(); e != nil {
		t.Fatal(e)
	}
}
func TestIsolationEveryInstallCommitCrash(t *testing.T) {
	for step := 2; step <= 7; step++ {
		t.Run(fmt.Sprint(step), func(t *testing.T) {
			m, s, n, g := isolationFixture(t)
			s.failAt = step
			e := m.EnsureGuard(g)
			if e == nil {
				e = m.EnsureCompanyRoute(g, n.tun, "192.0.2.5/32")
			}
			if e == nil && step <= 6 {
				t.Fatal("missing durable-write failure")
			}
			s.failAt = 0
			if e = m.Recover(); e != nil {
				t.Fatal(e)
			}
			if len(n.owned) != 0 || len(n.guards) != 0 {
				t.Fatal("crash left owned state")
			}
		})
	}
}
func TestIsolationEveryRecoveryCommitCrash(t *testing.T) {
	for step := 1; step <= 9; step++ {
		t.Run(fmt.Sprint(step), func(t *testing.T) {
			m, s, n, g := isolationFixture(t)
			installPair(t, m, n, g)
			s.failAt = s.writes + step
			_ = m.Recover()
			s.failAt = 0
			if e := m.Recover(); e != nil {
				t.Fatal(e)
			}
			if len(n.owned) != 0 || len(n.guards) != 0 {
				t.Fatal("recovery restart left state")
			}
		})
	}
}
func TestIsolationVPNDeletionFailureRetainsBothProtections(t *testing.T) {
	m, _, n, g := isolationFixture(t)
	installPair(t, m, n, g)
	n.failVPNDelete = true
	if e := m.Recover(); e == nil {
		t.Fatal("missing deletion failure")
	}
	if len(n.owned) != 2 || !n.guards[g.Sublayer].Complete() {
		t.Fatal("protection removed too early")
	}
	n.failVPNDelete = false
	if e := m.Recover(); e != nil {
		t.Fatal(e)
	}
}
func TestIsolationExternalRouteChangeRetainsGuard(t *testing.T) {
	m, s, n, g := isolationFixture(t)
	installPair(t, m, n, g)
	j, _ := s.Load()
	r := j.Pairs[0].VPN.Route
	r.Metric++
	n.owned[routeKey(r)] = r
	if e := m.CheckCompanyAddress(g, "192.0.2.5"); e == nil {
		t.Fatal("external route authorized")
	}
	if e := m.Recover(); e == nil {
		t.Fatal("external route removed")
	}
	if len(n.owned) != 2 || !n.guards[g.Sublayer].Complete() {
		t.Fatal("external change lost protection")
	}
}
func TestIsolationMissingGuardOrMetricDriftRevokesDial(t *testing.T) {
	for _, kind := range []string{"missing-guard", "changed-guard", "metric-drift", "missing-capture", "adapter-replaced"} {
		t.Run(kind, func(t *testing.T) {
			m, s, n, g := isolationFixture(t)
			installPair(t, m, n, g)
			switch kind {
			case "missing-guard":
				n.guards[g.Sublayer] = winwfp.Status{Sublayer: true}
			case "changed-guard":
				n.guardChanged = true
			case "metric-drift":
				a := n.tun
				a.Metric += 100
				n.adapters[a.GUID] = a
			case "missing-capture":
				j, _ := s.Load()
				delete(n.owned, routeKey(j.Pairs[0].Capture.Route))
			case "adapter-replaced":
				a := n.vpn
				a.LUID++
				n.adapters[a.GUID] = a
			}
			if e := m.CheckCompanyAddress(g, "192.0.2.5"); e == nil {
				t.Fatal("stale path authorized")
			}
		})
	}
}
func TestIsolationLeaseRetirementAndReconnect(t *testing.T) {
	m, s, n, g := isolationFixture(t)
	installPair(t, m, n, g)
	if e := m.RemoveCompanyRoute(g, "192.0.2.5/32"); e != nil {
		t.Fatal(e)
	}
	if len(n.owned) != 0 || !n.guards[g.Sublayer].Complete() {
		t.Fatal("lease retirement removed guard")
	}
	if e := m.EnsureCompanyRoute(g, n.tun, "192.0.2.6/32"); e != nil {
		t.Fatal(e)
	}
	j, _ := s.Load()
	if len(j.Pairs) != 1 {
		t.Fatal("retired pairs accumulated")
	}
	if e := m.ReleaseVPN(n.vpn); e != nil {
		t.Fatal(e)
	}
	if len(n.owned) != 0 || len(n.guards) != 0 {
		t.Fatal("release retained VPN state")
	}
	j, _ = s.Load()
	if j.Stopping {
		t.Fatal("release stopped coordinator")
	}
	next, e := winwfp.New(n.vpn, g.Executable, g.AppID)
	if e != nil {
		t.Fatal(e)
	}
	n.spec = next
	if e = m.EnsureGuard(next); e != nil {
		t.Fatal(e)
	}
	if e = m.EnsureCompanyRoute(next, n.tun, "192.0.2.7/32"); e != nil {
		t.Fatal(e)
	}
}
func TestIsolationRouteNeedsGuardAndMetricHeadroom(t *testing.T) {
	m, _, n, g := isolationFixture(t)
	if e := m.EnsureCompanyRoute(g, n.tun, "192.0.2.5/32"); e == nil || len(n.owned) != 0 {
		t.Fatal("route without journaled guard")
	}
	if e := m.EnsureGuard(g); e != nil {
		t.Fatal(e)
	}
	a := n.tun
	a.Metric = ^uint32(0)
	n.adapters[a.GUID] = a
	a = n.vpn
	a.Metric = 0
	n.adapters[a.GUID] = a
	if e := m.EnsureCompanyRoute(g, n.tun, "192.0.2.5/32"); e == nil || len(n.owned) != 0 {
		t.Fatal("overflow route accepted")
	}
}
