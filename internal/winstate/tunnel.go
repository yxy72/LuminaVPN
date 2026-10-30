package winstate

import (
	"errors"
	"fmt"
	"netlaunch/internal/winnet"
)

type AddressChange struct {
	Adapter winnet.Adapter `json:"adapter"`
	Address winnet.Address `json:"address"`
	State   string         `json:"state"`
}
type MTUChange struct {
	Adapter winnet.Adapter `json:"adapter"`
	Before  uint32         `json:"before"`
	After   uint32         `json:"after"`
	State   string         `json:"state"`
}

// TunnelBackend is an optional extension so route/DNS-only recovery remains
// available for older runs and backends with no tunnel-address records.
type TunnelBackend interface {
	Addresses() ([]winnet.Address, error)
	LookupAddress(winnet.Address) (*winnet.Address, error)
	AddAddress(winnet.Address) (winnet.Address, error)
	DeleteAddress(winnet.Address) error
	MTU(winnet.Adapter) (uint32, error)
	SetMTU(winnet.Adapter, uint32, uint32) error
}

func validTunnel(a winnet.Adapter) bool {
	return a.Index != 0 && a.LUID != 0 && a.GUID != "" && a.Type == 53 && !a.Hardware
}
func validateTunnelJournal(j Journal) error {
	for _, v := range j.Addresses {
		if !validState(v.State) || !validTunnel(v.Adapter) || v.Address.Validate() != nil || v.Adapter.Index != v.Address.InterfaceIndex || v.Adapter.LUID != v.Address.InterfaceLUID {
			return errors.New("invalid VPN address journal")
		}
	}
	for _, v := range j.MTU {
		if !validState(v.State) || !validTunnel(v.Adapter) || v.Before < 576 || v.Before > 65535 || !winnet.ValidVPNMTU(v.After) {
			return errors.New("invalid VPN MTU journal")
		}
	}
	return nil
}
func (m Manager) tunnel() (TunnelBackend, error) {
	n, ok := m.Native.(TunnelBackend)
	if !ok {
		return nil, errors.New("VPN address backend unavailable")
	}
	return n, nil
}
func (m Manager) tunnelAdapter(a winnet.Adapter) error {
	if !validTunnel(a) {
		return errors.New("owned virtual tunnel adapter required")
	}
	live, e := m.Native.Adapter(a.GUID)
	if e != nil {
		return e
	}
	if !winnet.SameAdapter(a, live) || !validTunnel(live) || live.Name != a.Name {
		return errors.New("VPN adapter identity changed")
	}
	return nil
}

func (m Manager) EnsureVPNAddress(a winnet.Adapter, ip string) (winnet.Address, error) {
	wanted, e := winnet.NewVPNAddress(a, ip)
	if e != nil {
		return wanted, e
	}
	n, e := m.tunnel()
	if e != nil {
		return wanted, e
	}
	unlock, e := m.Store.Lock()
	if e != nil {
		return wanted, e
	}
	defer unlock()
	j, e := m.load()
	if e != nil {
		return wanted, e
	}
	if e = m.active(j); e != nil {
		return wanted, e
	}
	if e = m.tunnelAdapter(a); e != nil {
		return wanted, e
	}
	actual, e := n.LookupAddress(wanted)
	if e != nil {
		return wanted, e
	}
	for i, v := range j.Addresses {
		if v.State == "restored" || !winnet.SameAddressKey(v.Address, wanted) {
			continue
		}
		if v.State == "restoring" {
			return wanted, errors.New("VPN address removal is incomplete")
		}
		if actual != nil {
			if !winnet.SameAdapter(a, v.Adapter) || !winnet.OwnedAddressEqual(v.Address, *actual) || !winnet.SameAddressAttributes(wanted, *actual) {
				return wanted, errors.New("journaled VPN address changed externally")
			}
			j.Addresses[i].Address = *actual
			j.Addresses[i].State = "applied"
			return *actual, m.Store.Save(j)
		}
		j.Addresses[i].State = "restored"
	}
	all, e := n.Addresses()
	if e != nil {
		return wanted, e
	}
	for _, v := range all {
		if v.IP == ip {
			return wanted, errors.New("VPN address exists outside this run")
		}
	}
	j.Addresses = append(j.Addresses, AddressChange{a, wanted, "planned"})
	if e = m.Store.Save(j); e != nil {
		return wanted, e
	}
	if e = m.active(j); e != nil {
		return wanted, e
	}
	if e = m.tunnelAdapter(a); e != nil {
		return wanted, e
	}
	created, e := n.AddAddress(wanted)
	if e != nil {
		return wanted, e
	}
	if !winnet.OwnedAddressEqual(wanted, created) {
		return wanted, errors.New("VPN address readback differs")
	}
	j.Addresses[len(j.Addresses)-1] = AddressChange{a, created, "applied"}
	return created, m.Store.Save(j)
}
func (m Manager) SetVPNMTU(a winnet.Adapter, desired uint32) error {
	if !winnet.ValidVPNMTU(desired) {
		return errors.New("VPN MTU must be between 576 and 1500")
	}
	n, e := m.tunnel()
	if e != nil {
		return e
	}
	unlock, e := m.Store.Lock()
	if e != nil {
		return e
	}
	defer unlock()
	j, e := m.load()
	if e != nil {
		return e
	}
	if e = m.active(j); e != nil {
		return e
	}
	if e = m.tunnelAdapter(a); e != nil {
		return e
	}
	before, e := n.MTU(a)
	if e != nil {
		return e
	}
	if before < 576 || before > 65535 {
		return errors.New("unsupported original VPN MTU")
	}
	index := -1
	for i, v := range j.MTU {
		if v.State == "restored" || !winnet.SameAdapter(v.Adapter, a) {
			continue
		}
		if v.State == "restoring" || v.After != desired {
			return errors.New("restore previous MTU intent first")
		}
		if before != v.Before && before != v.After {
			return errors.New("VPN MTU changed externally")
		}
		index = i
	}
	if index < 0 {
		if before == desired {
			return nil
		} // No change and no ownership claim.
		j.MTU = append(j.MTU, MTUChange{a, before, desired, "planned"})
		index = len(j.MTU) - 1
	}
	if e = m.Store.Save(j); e != nil {
		return e
	}
	if e = m.active(j); e != nil {
		return e
	}
	if e = m.tunnelAdapter(a); e != nil {
		return e
	}
	if before != desired {
		if e = n.SetMTU(a, before, desired); e != nil {
			return e
		}
	}
	actual, e := n.MTU(a)
	if e != nil {
		return e
	}
	if actual != desired {
		return errors.New("VPN MTU readback differs")
	}
	j.MTU[index].State = "applied"
	return m.Store.Save(j)
}

func (m Manager) restoreRoute(j *Journal, i int, boot string) error {
	return m.restoreRouteChange(j, &j.Routes[i], boot)
}
func (m Manager) restoreRouteChange(j *Journal, entry *RouteChange, boot string) error {
	r := *entry
	if r.State == "restored" {
		return nil
	}
	if r.State != "restoring" {
		entry.State = "restoring"
		if e := m.Store.Save(*j); e != nil {
			entry.State = r.State
			return e
		}
	}
	actual, e := m.Native.Lookup(r.Route)
	if e == nil && actual != nil {
		if boot != j.BootID {
			e = errors.New("route survived a boot change; ownership is not proven")
		} else if !winnet.OwnedEqual(r.Route, *actual) {
			e = errors.New("route changed externally; deletion refused")
		} else {
			e = m.Native.Delete(r.Route)
		}
		if e == nil {
			actual, e = m.Native.Lookup(r.Route)
			if e == nil && actual != nil {
				e = errors.New("owned route remains")
			}
		}
	}
	if e != nil {
		return fmt.Errorf("restore route %s: %w", r.Route.Prefix, e)
	}
	entry.State = "restored"
	if e = m.Store.Save(*j); e != nil {
		entry.State = "restoring"
	}
	return e
}

// RemoveRoute retires only the exact journaled route. This is the live lease
// revocation path; unlike Recover it leaves the coordinator active.
func (m Manager) RemoveRoute(wanted winnet.Route) error {
	if e := wanted.Validate(); e != nil {
		return e
	}
	unlock, e := m.Store.Lock()
	if e != nil {
		return e
	}
	defer unlock()
	j, e := m.load()
	if e != nil {
		return e
	}
	if e = m.active(j); e != nil {
		return e
	}
	for i, r := range j.Routes {
		if r.State == "restored" || !winnet.SameKey(r.Route, wanted) {
			continue
		}
		if !winnet.OwnedEqual(r.Route, wanted) {
			return errors.New("route removal intent differs")
		}
		return m.restoreRoute(&j, i, j.BootID)
	}
	return nil
}

// ReleaseVPN runs after company grants and sockets have been revoked and the
// old OpenConnect child has stopped. It leaves other adapter routes/DNS alone.
func (m Manager) ReleaseVPN(a winnet.Adapter) error {
	if !validTunnel(a) {
		return errors.New("invalid VPN adapter")
	}
	unlock, e := m.Store.Lock()
	if e != nil {
		return e
	}
	defer unlock()
	j, e := m.load()
	if e != nil {
		return e
	}
	if e = m.active(j); e != nil {
		return e
	}
	var failures []error
	for i := len(j.Routes) - 1; i >= 0; i-- {
		r := j.Routes[i].Route
		if r.InterfaceIndex == a.Index && r.InterfaceLUID == a.LUID {
			if e = m.restoreRoute(&j, i, j.BootID); e != nil {
				failures = append(failures, e)
			}
		}
	}
	if e = m.restoreIsolation(&j, &a, j.BootID); e != nil {
		failures = append(failures, e)
	}
	if e = m.restoreTunnel(&j, &a, j.BootID); e != nil {
		failures = append(failures, e)
	}
	return errors.Join(failures...)
}
func (m Manager) restoreTunnel(j *Journal, only *winnet.Adapter, boot string) error {
	if len(j.Addresses) == 0 && len(j.MTU) == 0 {
		return nil
	}
	n, e := m.tunnel()
	if e != nil {
		return e
	}
	var failures []error
	for i := len(j.Addresses) - 1; i >= 0; i-- {
		v := j.Addresses[i]
		if v.State == "restored" || (only != nil && !winnet.SameAdapter(*only, v.Adapter)) {
			continue
		}
		j.Addresses[i].State = "restoring"
		if e = m.Store.Save(*j); e != nil {
			j.Addresses[i].State = v.State
			failures = append(failures, e)
			continue
		}
		actual, err := n.LookupAddress(v.Address)
		if err == nil && actual != nil {
			if boot != j.BootID {
				err = errors.New("address survived boot change; ownership unproven")
			} else if !winnet.OwnedAddressEqual(v.Address, *actual) {
				err = errors.New("address changed externally; deletion refused")
			} else {
				err = n.DeleteAddress(v.Address)
			}
			if err == nil {
				actual, err = n.LookupAddress(v.Address)
				if err == nil && actual != nil {
					err = errors.New("owned address remains")
				}
			}
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("restore VPN address: %w", err))
			continue
		}
		j.Addresses[i].State = "restored"
		if e = m.Store.Save(*j); e != nil {
			j.Addresses[i].State = "restoring"
			failures = append(failures, e)
		}
	}
	for i := len(j.MTU) - 1; i >= 0; i-- {
		v := j.MTU[i]
		if v.State == "restored" || (only != nil && !winnet.SameAdapter(*only, v.Adapter)) {
			continue
		}
		j.MTU[i].State = "restoring"
		if e = m.Store.Save(*j); e != nil {
			j.MTU[i].State = v.State
			failures = append(failures, e)
			continue
		}
		live, err := m.Native.Adapter(v.Adapter.GUID)
		if errors.Is(err, winnet.ErrAdapterAbsent) {
			err = nil
		} else if err == nil {
			current, readErr := n.MTU(live)
			err = readErr
			if err == nil && current != v.Before {
				if boot != j.BootID || !winnet.SameAdapter(v.Adapter, live) {
					err = errors.New("MTU adapter generation changed")
				} else if current != v.After {
					err = errors.New("MTU changed externally; restoration refused")
				} else {
					err = n.SetMTU(live, current, v.Before)
				}
				if err == nil {
					current, err = n.MTU(live)
					if err == nil && current != v.Before {
						err = errors.New("MTU restoration readback differs")
					}
				}
			}
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("restore VPN MTU: %w", err))
			continue
		}
		j.MTU[i].State = "restored"
		if e = m.Store.Save(*j); e != nil {
			j.MTU[i].State = "restoring"
			failures = append(failures, e)
		}
	}
	return errors.Join(failures...)
}
