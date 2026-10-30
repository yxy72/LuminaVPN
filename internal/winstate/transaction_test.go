package winstate

import (
	"encoding/json"
	"errors"
	"netlaunch/internal/winnet"
	"sync"
	"testing"
)

type memoryStore struct {
	mu             sync.Mutex
	disk           []byte
	writes, failAt int
}

func (s *memoryStore) Lock() (func(), error) { s.mu.Lock(); return s.mu.Unlock, nil }
func (s *memoryStore) Load() (Journal, error) {
	var j Journal
	e := json.Unmarshal(s.disk, &j)
	return j, e
}
func (s *memoryStore) Save(j Journal) error {
	s.writes++
	if s.writes == s.failAt {
		return errors.New("simulated durable write failure")
	}
	b, e := json.Marshal(j)
	if e == nil {
		s.disk = b
	}
	return e
}

type fakeNative struct {
	boot                string
	routes              map[string]winnet.Route
	adapter             winnet.Adapter
	dns                 winnet.DNSSettings
	adds, deletes, sets int
	dnsWriteFails       bool
}

func (n *fakeNative) BootID() (string, error) { return n.boot, nil }
func (n *fakeNative) Lookup(r winnet.Route) (*winnet.Route, error) {
	v, ok := n.routes[r.Prefix]
	if !ok {
		return nil, nil
	}
	return &v, nil
}
func (n *fakeNative) Add(r winnet.Route) (winnet.Route, error) {
	n.adds++
	if _, exists := n.routes[r.Prefix]; exists {
		return r, errors.New("already exists")
	}
	n.routes[r.Prefix] = r
	return r, nil
}
func (n *fakeNative) Delete(r winnet.Route) error {
	n.deletes++
	delete(n.routes, r.Prefix)
	return nil
}
func (n *fakeNative) Adapter(g string) (winnet.Adapter, error) {
	if g != n.adapter.GUID {
		return winnet.Adapter{}, errors.New("missing adapter")
	}
	return n.adapter, nil
}
func (n *fakeNative) DNS(winnet.Adapter) (winnet.DNSSettings, error) { return n.dns, nil }
func (n *fakeNative) SetDNS(_ winnet.Adapter, d winnet.DNSSettings) error {
	n.sets++
	if n.dnsWriteFails {
		return errors.New("simulated DNS API failure")
	}
	n.dns = d
	return nil
}

func fixture(t *testing.T) (Manager, *memoryStore, *fakeNative, winnet.Route) {
	t.Helper()
	s := &memoryStore{}
	if e := s.Save(Journal{Version: 1, BootID: "boot-1"}); e != nil {
		t.Fatal(e)
	}
	n := &fakeNative{boot: "boot-1", routes: map[string]winnet.Route{}, adapter: winnet.Adapter{Index: 2, LUID: 22, GUID: "physical-guid", Up: true}}
	r, e := winnet.NewRoute(n.adapter, "192.0.2.5/32", "0.0.0.0", 317)
	if e != nil {
		t.Fatal(e)
	}
	return Manager{s, n}, s, n, r
}

func TestRouteCrashBetweenMutationAndCommit(t *testing.T) {
	m, s, n, r := fixture(t)
	s.failAt = 3 // initial journal, planned intent, then failed applied commit
	if e := m.EnsureRoute(r); e == nil {
		t.Fatal("missing injected error")
	}
	j, _ := s.Load()
	if j.Routes[0].State != "planned" || n.adds != 1 {
		t.Fatal("intent not durable")
	}
	s.failAt = 0
	if e := m.Recover(); e != nil {
		t.Fatal(e)
	}
	if n.deletes != 1 || len(n.routes) != 0 {
		t.Fatal("planned route was not recovered")
	}
	if e := m.Recover(); e != nil || n.deletes != 1 {
		t.Fatal("recovery not idempotent", e)
	}
	if e := m.EnsureRoute(r); e == nil {
		t.Fatal("new route accepted after recovery")
	}
}

func TestIntentWriteFailurePreventsNativeChange(t *testing.T) {
	m, s, n, r := fixture(t)
	s.failAt = 2
	if e := m.EnsureRoute(r); e == nil {
		t.Fatal("missing failure")
	}
	if n.adds != 0 || len(n.routes) != 0 {
		t.Fatal("changed kernel without durable intent")
	}
	s.failAt = 3
	if e := m.SetDNS(n.adapter, winnet.DNSSettings{NameServers: "127.0.0.1"}); e == nil {
		t.Fatal("missing DNS intent failure")
	}
	if n.sets != 0 {
		t.Fatal("changed DNS without durable intent")
	}
}

func TestRecoveryRetainsExternallyChangedRoute(t *testing.T) {
	m, s, n, r := fixture(t)
	if e := m.EnsureRoute(r); e != nil {
		t.Fatal(e)
	}
	changed := r
	changed.Metric++
	n.routes[r.Prefix] = changed
	if e := m.Recover(); e == nil {
		t.Fatal("external route overwritten")
	}
	j, _ := s.Load()
	if n.deletes != 0 || j.Routes[0].State != "restoring" {
		t.Fatal("external route forgotten")
	}
	n.routes[r.Prefix] = r
	if e := m.Recover(); e != nil {
		t.Fatal("retry failed", e)
	}
}

func TestDNSCrashRestoresAutomaticAfterReboot(t *testing.T) {
	m, s, n, _ := fixture(t)
	s.failAt = 3
	if e := m.SetDNS(n.adapter, winnet.DNSSettings{NameServers: "127.0.0.1"}); e == nil {
		t.Fatal("missing commit failure")
	}
	j, _ := s.Load()
	if j.DNS[0].State != "planned" || j.DNS[0].Before.NameServers != "" {
		t.Fatal("automatic DNS not saved")
	}
	n.boot = "boot-2"
	n.adapter.Index = 7
	n.adapter.LUID = 77
	s.failAt = 0
	if e := m.Recover(); e != nil {
		t.Fatal(e)
	}
	if n.dns.NameServers != "" || n.sets != 2 {
		t.Fatal("automatic DNS not restored")
	}
}

func TestRecoveryContinuesAfterDNSFailure(t *testing.T) {
	m, s, n, r := fixture(t)
	if e := m.EnsureRoute(r); e != nil {
		t.Fatal(e)
	}
	if e := m.SetDNS(n.adapter, winnet.DNSSettings{NameServers: "127.0.0.1"}); e != nil {
		t.Fatal(e)
	}
	n.dns = winnet.DNSSettings{NameServers: "9.9.9.9"}
	if e := m.Recover(); e == nil {
		t.Fatal("external DNS overwritten")
	}
	j, _ := s.Load()
	if n.dns.NameServers != "9.9.9.9" || n.sets != 1 || len(n.routes) != 0 || j.DNS[0].State != "applied" || j.Routes[0].State != "restored" {
		t.Fatal("recovery failed to preserve independent outcomes")
	}
}

func TestRouteOwnershipDoesNotCrossBoot(t *testing.T) {
	m, _, n, r := fixture(t)
	if e := m.EnsureRoute(r); e != nil {
		t.Fatal(e)
	}
	n.boot = "boot-2"
	if e := m.Recover(); e == nil || n.deletes != 0 {
		t.Fatal("deleted unproven post-boot route", e)
	}
}

func TestInvalidRouteCannotPoisonRecoveryJournal(t *testing.T) {
	m, s, n, r := fixture(t)
	if e := m.EnsureRoute(r); e != nil {
		t.Fatal(e)
	}
	before := string(s.disk)
	invalid := r
	invalid.Prefix = "0.0.0.0/0"
	if e := m.EnsureRoute(invalid); e == nil {
		t.Fatal("default route accepted")
	}
	if string(s.disk) != before || n.adds != 1 {
		t.Fatal("invalid request poisoned recovery journal")
	}
	if e := m.Recover(); e != nil {
		t.Fatal("existing route could not recover", e)
	}
}

func TestCompletedRouteGenerationsRemainBounded(t *testing.T) {
	m, s, _, r := fixture(t)
	for i := 0; i < 200; i++ {
		if e := m.EnsureRoute(r); e != nil {
			t.Fatal(e)
		}
		if e := m.RemoveRoute(r); e != nil {
			t.Fatal(e)
		}
	}
	j, e := s.Load()
	if e != nil {
		t.Fatal(e)
	}
	if len(j.Routes) > 1 {
		t.Fatal("retired generations accumulated")
	}
}
