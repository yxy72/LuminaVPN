package winstate

import (
	"errors"
	"netlaunch/internal/winwfp"
	"testing"
)

type ipv6Fake struct {
	fakeNative
	store         *memoryStore
	status        winwfp.IPv6Status
	adds, removes int
	changed       bool
}

func (n *ipv6Fake) InspectIPv6(winwfp.IPv6Spec) (winwfp.IPv6Status, error) {
	if n.changed {
		return n.status, errors.New("external WFP edit")
	}
	return n.status, nil
}
func (n *ipv6Fake) AddIPv6(s winwfp.IPv6Spec) error {
	j, e := n.store.Load()
	if e != nil || len(j.IPv6Guards) != 1 || j.IPv6Guards[0].Spec != s || j.IPv6Guards[0].State != "planned" {
		return errors.New("mutation before durable intent")
	}
	n.adds++
	n.status = winwfp.IPv6Status{Provider: true, Sublayer: true, Outbound: true, Forward: true}
	return nil
}
func (n *ipv6Fake) RemoveIPv6(winwfp.IPv6Spec) error {
	n.removes++
	n.status = winwfp.IPv6Status{}
	return nil
}
func ipv6Fixture(t *testing.T) (Manager, *memoryStore, *ipv6Fake, winwfp.IPv6Spec) {
	t.Helper()
	store := &memoryStore{}
	if e := store.Save(Journal{Version: 1, BootID: "boot"}); e != nil {
		t.Fatal(e)
	}
	n := &ipv6Fake{fakeNative: fakeNative{boot: "boot"}, store: store}
	s, e := winwfp.NewIPv6()
	if e != nil {
		t.Fatal(e)
	}
	return Manager{Store: store, Native: n}, store, n, s
}
func TestGlobalIPv6DurableIntentAndReleaseAfterExactExitGate(t *testing.T) {
	m, store, n, s := ipv6Fixture(t)
	if e := m.EnsureIPv6(s); e != nil {
		t.Fatal(e)
	}
	if e := m.CheckIPv6(s); e != nil {
		t.Fatal(e)
	}
	if e := m.RecoverNetwork(); e != nil {
		t.Fatal(e)
	}
	if n.removes != 0 || !n.status.Complete() {
		t.Fatal("guard released before external exact-exit gate")
	}
	j, _ := store.Load()
	if CheckRecovered(j) == nil {
		t.Fatal("pending guard reported recovered")
	}
	if e := m.ReleaseIPv6(); e != nil {
		t.Fatal(e)
	}
	j, _ = store.Load()
	if e := CheckRecovered(j); e != nil {
		t.Fatal(e)
	}
	if n.adds != 1 || n.removes != 1 {
		t.Fatal(n.adds, n.removes)
	}
}
func TestGlobalIPv6FailedIntentAndUnknownNeverGreen(t *testing.T) {
	m, store, n, s := ipv6Fixture(t)
	store.failAt = store.writes + 1
	if m.EnsureIPv6(s) == nil || n.adds != 0 {
		t.Fatal("write failure permitted mutation")
	}
	store.failAt = 0
	if e := m.EnsureIPv6(s); e != nil {
		t.Fatal(e)
	}
	n.changed = true
	if m.CheckIPv6(s) == nil || m.Recover() == nil || n.removes != 0 {
		t.Fatal("unknown/foreign guard deleted or passed")
	}
}
