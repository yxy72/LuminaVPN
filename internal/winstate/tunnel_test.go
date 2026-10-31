package winstate

import (
	"errors"
	"netlaunch/internal/winnet"
	"testing"
)

type fakeTunnel struct {
	*fakeNative
	addresses                            []winnet.Address
	mtu                                  uint32
	mtuError                             error
	addressAdds, addressDeletes, mtuSets int
}

func (n *fakeTunnel) Addresses() ([]winnet.Address, error) {
	return append([]winnet.Address(nil), n.addresses...), nil
}
func (n *fakeTunnel) LookupAddress(a winnet.Address) (*winnet.Address, error) {
	for _, v := range n.addresses {
		if winnet.SameAddressKey(a, v) {
			copy := v
			return &copy, nil
		}
	}
	return nil, nil
}
func (n *fakeTunnel) AddAddress(a winnet.Address) (winnet.Address, error) {
	n.addressAdds++
	for _, v := range n.addresses {
		if a.IP == v.IP {
			return a, errors.New("existing address")
		}
	}
	a.Created = uint64(n.addressAdds)
	n.addresses = append(n.addresses, a)
	return a, nil
}
func (n *fakeTunnel) DeleteAddress(a winnet.Address) error {
	n.addressDeletes++
	for i, v := range n.addresses {
		if winnet.SameAddressKey(a, v) {
			if !winnet.OwnedAddressEqual(a, v) {
				return errors.New("foreign address")
			}
			n.addresses = append(n.addresses[:i], n.addresses[i+1:]...)
			return nil
		}
	}
	return nil
}
func (n *fakeTunnel) MTU(winnet.Adapter) (uint32, error) { return n.mtu, n.mtuError }
func (n *fakeTunnel) SetMTU(_ winnet.Adapter, before, after uint32) error {
	if n.mtu != before {
		return errors.New("external MTU")
	}
	n.mtuSets++
	n.mtu = after
	return nil
}
func tunnelFixture(t *testing.T) (Manager, *memoryStore, *fakeTunnel, winnet.Adapter) {
	t.Helper()
	m, s, n, _ := fixture(t)
	a := winnet.Adapter{Index: 7, LUID: 77, GUID: "vpn-guid", Name: "NL-VPN", Type: 53, Up: true}
	n.adapter = a
	nt := &fakeTunnel{fakeNative: n, mtu: 1500}
	m.Native = nt
	return m, s, nt, a
}
func TestVPNAddressWriteBoundaries(t *testing.T) {
	for _, fail := range []int{2, 3} {
		t.Run(map[int]string{2: "before_native_add", 3: "after_native_add"}[fail], func(t *testing.T) {
			m, s, n, a := tunnelFixture(t)
			s.failAt = fail
			if _, e := m.EnsureVPNAddress(a, "192.0.2.8"); e == nil {
				t.Fatal("missing failure")
			}
			if n.addressAdds != fail-2 {
				t.Fatal("wrong native write boundary")
			}
			s.failAt = 0
			if e := m.Recover(); e != nil {
				t.Fatal(e)
			}
			if len(n.addresses) != 0 {
				t.Fatal("address remained after recovery")
			}
		})
	}
}
func TestVPNAddressIdentityAndDuplicates(t *testing.T) {
	m, s, n, a := tunnelFixture(t)
	v, e := m.EnsureVPNAddress(a, "192.0.2.8")
	if e != nil {
		t.Fatal(e)
	}
	if v.Created == 0 {
		t.Fatal("creation identity omitted")
	}
	if _, e = m.EnsureVPNAddress(a, v.IP); e != nil || n.addressAdds != 1 {
		t.Fatal("non-idempotent ensure", e)
	}
	n.addresses[0].Created++
	if _, e = m.EnsureVPNAddress(a, v.IP); e == nil {
		t.Fatal("replaced address accepted")
	}
	if e = m.Recover(); e == nil || n.addressDeletes != 0 {
		t.Fatal("foreign address deleted", e)
	}
	j, _ := s.Load()
	if j.Addresses[0].State != "restoring" {
		t.Fatal("failed ownership forgotten")
	}
	// A conflicting address on another adapter is never claimed or deleted.
	m, s, n, a = tunnelFixture(t)
	other, _ := winnet.NewVPNAddress(a, "192.0.2.8")
	other.InterfaceLUID++
	other.InterfaceIndex++
	n.addresses = []winnet.Address{other}
	if _, e = m.EnsureVPNAddress(a, other.IP); e == nil {
		t.Fatal("duplicate address accepted")
	}
	j, _ = s.Load()
	if n.addressAdds != 0 || len(j.Addresses) != 0 {
		t.Fatal("foreign address claimed")
	}
}
func TestVPNAddressRecoveryAfterAdapterGone(t *testing.T) {
	m, _, n, a := tunnelFixture(t)
	if _, e := m.EnsureVPNAddress(a, "192.0.2.8"); e != nil {
		t.Fatal(e)
	}
	n.addresses = nil
	n.boot = "boot-2"
	if e := m.Recover(); e != nil || n.addressDeletes != 0 {
		t.Fatal("absent address was not safely forgotten", e)
	}
}
func TestVPNAddressOwnershipDoesNotCrossBoot(t *testing.T) {
	m, _, n, a := tunnelFixture(t)
	if _, e := m.EnsureVPNAddress(a, "192.0.2.8"); e != nil {
		t.Fatal(e)
	}
	n.boot = "boot-2"
	if e := m.Recover(); e == nil || n.addressDeletes != 0 {
		t.Fatal("post-boot address deleted", e)
	}
}
func TestVPNMTUCrashAndExternalChange(t *testing.T) {
	m, s, n, a := tunnelFixture(t)
	s.failAt = 3
	if e := m.SetVPNMTU(a, 1280); e == nil || n.mtu != 1280 {
		t.Fatal("missing crash boundary", e)
	}
	s.failAt = 0
	if e := m.Recover(); e != nil || n.mtu != 1500 {
		t.Fatal("MTU not restored", e)
	}
	m, s, n, a = tunnelFixture(t)
	if e := m.SetVPNMTU(a, 1280); e != nil {
		t.Fatal(e)
	}
	n.mtu = 1400
	if e := m.Recover(); e == nil || n.mtu != 1400 {
		t.Fatal("external MTU replaced", e)
	}
	j, _ := s.Load()
	if j.MTU[0].State != "restoring" {
		t.Fatal("failed MTU entry forgotten")
	}
}
func TestVPNMTURefusesPhysicalAndStaleAdapter(t *testing.T) {
	m, _, n, a := tunnelFixture(t)
	bad := a
	bad.Hardware = true
	if e := m.SetVPNMTU(bad, 1280); e == nil {
		t.Fatal("physical MTU accepted")
	}
	bad = a
	bad.LUID++
	if e := m.SetVPNMTU(bad, 1280); e == nil {
		t.Fatal("reused index accepted")
	}
	if e := m.SetVPNMTU(a, 1501); e == nil {
		t.Fatal("oversized VPN MTU accepted")
	}
	if n.mtuSets != 0 {
		t.Fatal("mutated MTU after validation failure")
	}
}

func TestVPNMTURemovedIPv4Row(t *testing.T) {
	for _, scenario := range []string{"same_down", "still_up", "new_generation", "new_boot", "other_error"} {
		t.Run(scenario, func(t *testing.T) {
			m, store, n, a := tunnelFixture(t)
			if err := m.SetVPNMTU(a, 1280); err != nil {
				t.Fatal(err)
			}
			n.adapter.Up = false
			n.mtuError = winnet.ErrIPInterfaceAbsent
			switch scenario {
			case "still_up":
				n.adapter.Up = true
			case "new_generation":
				n.adapter.LUID++
			case "new_boot":
				n.boot = "next-boot"
			case "other_error":
				n.mtuError = errors.New("access denied")
			}
			err := m.Recover()
			wantSuccess := scenario == "same_down"
			if (err == nil) != wantSuccess {
				t.Fatalf("recovery success=%v, wanted %v", err == nil, wantSuccess)
			}
			if n.mtuSets != 1 {
				t.Fatal("wrote an absent or unowned interface")
			}
			j, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if (j.MTU[0].State == "restored") != wantSuccess {
				t.Fatal("incorrect durable recovery state")
			}
		})
	}
}
func TestLiveVPNReleaseLeavesPhysicalRoutesAndDNS(t *testing.T) {
	m, s, n, a := tunnelFixture(t)
	corp, _ := winnet.NewRoute(a, "192.0.2.53/32", "0.0.0.0", 317)
	physical := a
	physical.Index = 2
	physical.LUID = 22
	physical.GUID = "physical"
	endpoint, _ := winnet.NewRoute(physical, "192.0.2.1/32", "192.0.2.254", 317)
	for _, r := range []winnet.Route{corp, endpoint} {
		if e := m.EnsureRoute(r); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := m.EnsureVPNAddress(a, "192.0.2.8"); e != nil {
		t.Fatal(e)
	}
	if e := m.SetVPNMTU(a, 1280); e != nil {
		t.Fatal(e)
	}
	if e := m.SetDNS(a, winnet.DNSSettings{NameServers: "127.0.0.1"}); e != nil {
		t.Fatal(e)
	}
	if e := m.ReleaseVPN(a); e != nil {
		t.Fatal(e)
	}
	j, _ := s.Load()
	if j.Stopping || len(n.routes) != 1 || n.routes[endpoint.Prefix] != endpoint || len(n.addresses) != 0 || n.mtu != 1500 || n.dns.NameServers != "127.0.0.1" {
		t.Fatal("release touched other ownership or left VPN state")
	}
	if e := m.EnsureRoute(corp); e != nil {
		t.Fatal("could not create next generation route", e)
	}
}
func TestLiveRouteRemovalCrashCannotResurrect(t *testing.T) {
	m, s, n, r := fixture(t)
	if e := m.EnsureRoute(r); e != nil {
		t.Fatal(e)
	}
	s.failAt = s.writes + 2 // deletion succeeded, restored commit failed
	if e := m.RemoveRoute(r); e == nil || len(n.routes) != 0 {
		t.Fatal("missing delete crash boundary", e)
	}
	s.failAt = 0
	if e := m.EnsureRoute(r); e == nil || n.adds != 1 {
		t.Fatal("incomplete removal resurrected route", e)
	}
	if e := m.RemoveRoute(r); e != nil {
		t.Fatal("retry removal", e)
	}
	if e := m.EnsureRoute(r); e != nil || n.adds != 2 {
		t.Fatal("new route refused after removal complete", e)
	}
}
func TestLiveRouteRemovalNeedsDurableIntent(t *testing.T) {
	m, s, n, r := fixture(t)
	if e := m.EnsureRoute(r); e != nil {
		t.Fatal(e)
	}
	s.failAt = s.writes + 1
	if e := m.RemoveRoute(r); e == nil || n.deletes != 0 {
		t.Fatal("deleted without removal intent", e)
	}
}
