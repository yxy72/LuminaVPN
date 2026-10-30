// Package winstate journals native Windows changes before they happen. Both
// the coordinator and its independent recovery process use this transaction
// boundary; an incomplete write never licenses an unrecorded native mutation.
package winstate

import (
	"errors"
	"fmt"
	"netlaunch/internal/winnet"
	"slices"
)

type RouteChange struct {
	Route winnet.Route `json:"route"`
	State string       `json:"state"`
}
type DNSChange struct {
	Adapter winnet.Adapter     `json:"adapter"`
	Before  winnet.DNSSettings `json:"before"`
	After   winnet.DNSSettings `json:"after"`
	State   string             `json:"state"`
}
type Journal struct {
	Version   int             `json:"version"`
	BootID    string          `json:"boot_id"`
	Stopping  bool            `json:"stopping"`
	Routes    []RouteChange   `json:"routes"`
	DNS       []DNSChange     `json:"dns"`
	Addresses []AddressChange `json:"addresses,omitempty"`
	MTU       []MTUChange     `json:"mtu,omitempty"`
	Guards    []GuardChange   `json:"guards,omitempty"`
	Pairs     []PairChange    `json:"pairs,omitempty"`
}
type Storage interface {
	Lock() (func(), error)
	Load() (Journal, error)
	Save(Journal) error
}
type Backend interface {
	BootID() (string, error)
	Lookup(winnet.Route) (*winnet.Route, error)
	Add(winnet.Route) (winnet.Route, error)
	Delete(winnet.Route) error
	Adapter(string) (winnet.Adapter, error)
	DNS(winnet.Adapter) (winnet.DNSSettings, error)
	SetDNS(winnet.Adapter, winnet.DNSSettings) error
}
type Manager struct {
	Store  Storage
	Native Backend
}

func (m Manager) load() (Journal, error) {
	j, e := m.Store.Load()
	if e != nil {
		return j, e
	}
	if j.Version != 1 || j.BootID == "" {
		return j, errors.New("invalid Windows recovery journal")
	}
	for _, r := range j.Routes {
		if !validState(r.State) || r.Route.Validate() != nil {
			return j, errors.New("invalid route journal state")
		}
	}
	for _, d := range j.DNS {
		if !validState(d.State) || d.Adapter.GUID == "" || d.Before.Validate() != nil || d.After.Validate() != nil {
			return j, errors.New("invalid DNS journal state")
		}
	}
	if e := validateTunnelJournal(j); e != nil {
		return j, e
	}
	if e := validateIsolation(j); e != nil {
		return j, e
	}
	// Completed entries have no remaining authority. Compact them on the next
	// transaction so frequent DNS rotation cannot exhaust the bounded journal.
	j.Routes = slices.DeleteFunc(j.Routes, func(v RouteChange) bool { return v.State == "restored" })
	j.DNS = slices.DeleteFunc(j.DNS, func(v DNSChange) bool { return v.State == "restored" })
	j.Addresses = slices.DeleteFunc(j.Addresses, func(v AddressChange) bool { return v.State == "restored" })
	j.MTU = slices.DeleteFunc(j.MTU, func(v MTUChange) bool { return v.State == "restored" })
	j.Pairs = slices.DeleteFunc(j.Pairs, pairDone)
	j.Guards = slices.DeleteFunc(j.Guards, func(v GuardChange) bool { return v.State == "restored" })
	return j, nil
}
func validState(s string) bool {
	return s == "planned" || s == "applied" || s == "restoring" || s == "restored"
}
func (m Manager) active(j Journal) error {
	if j.Stopping {
		return errors.New("recovery has started")
	}
	boot, e := m.Native.BootID()
	if e != nil {
		return e
	}
	if boot != j.BootID {
		return errors.New("computer restarted; recover the previous run first")
	}
	return nil
}

func (m Manager) EnsureRoute(wanted winnet.Route) error {
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
	actual, e := m.Native.Lookup(wanted)
	if e != nil {
		return e
	}
	for i, r := range j.Routes {
		if r.State == "restored" || !winnet.SameKey(r.Route, wanted) {
			continue
		}
		if r.State == "restoring" {
			return errors.New("route removal is incomplete")
		}
		if actual != nil && winnet.OwnedEqual(r.Route, *actual) && winnet.OwnedEqual(r.Route, wanted) {
			j.Routes[i].State = "applied"
			return m.Store.Save(j)
		}
		if actual != nil {
			return errors.New("journaled route changed externally")
		}
		j.Routes[i].State = "restored"
	}
	if actual != nil {
		return errors.New("route exists outside this run")
	}
	j.Routes = append(j.Routes, RouteChange{Route: wanted, State: "planned"})
	if e = m.Store.Save(j); e != nil {
		return e
	}
	// Recheck after the durable write. Add also refuses an existing native key.
	if e = m.active(j); e != nil {
		return e
	}
	created, e := m.Native.Add(wanted)
	if e != nil {
		return e
	}
	if !winnet.OwnedEqual(wanted, created) {
		return errors.New("native route readback differs from intent")
	}
	j.Routes[len(j.Routes)-1].State = "applied"
	return m.Store.Save(j)
}

func (m Manager) SetDNS(adapter winnet.Adapter, desired winnet.DNSSettings) error {
	if e := desired.Validate(); e != nil {
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
	live, e := m.Native.Adapter(adapter.GUID)
	if e != nil {
		return e
	}
	if live.Index != adapter.Index || live.LUID != adapter.LUID || !live.Up {
		return errors.New("DNS adapter changed before takeover")
	}
	current, e := m.Native.DNS(live)
	if e != nil {
		return e
	}
	// Profile-scoped resolvers can override the static list; preserve them and
	// require explicit support before attempting takeover on such a profile.
	if current.ProfileNameServers != "" || desired.ProfileNameServers != "" {
		return errors.New("profile DNS override is not supported for takeover")
	}
	index := -1
	for i, d := range j.DNS {
		if d.State == "restored" || d.Adapter.GUID != adapter.GUID {
			continue
		}
		if !winnet.SameDNS(current, d.After) && !winnet.SameDNS(current, d.Before) {
			return errors.New("DNS changed outside this run")
		}
		index = i
		if winnet.SameDNS(current, desired) && winnet.SameDNS(d.After, desired) {
			j.DNS[i].State = "applied"
			return m.Store.Save(j)
		}
		if !winnet.SameDNS(d.After, desired) {
			return errors.New("finish restoring the existing DNS change before replacing its intent")
		}
	}
	if index < 0 {
		if winnet.SameDNS(current, desired) {
			return errors.New("requested DNS already exists outside this run")
		}
		j.DNS = append(j.DNS, DNSChange{Adapter: adapter, Before: current, After: desired, State: "planned"})
		index = len(j.DNS) - 1
	}
	if e = m.Store.Save(j); e != nil {
		return e
	}
	if e = m.active(j); e != nil {
		return e
	}
	before, e := m.Native.DNS(live)
	if e != nil {
		return e
	}
	if !winnet.SameDNS(before, current) {
		return errors.New("DNS changed during takeover preparation")
	}
	if e = m.Native.SetDNS(live, desired); e != nil {
		return e
	}
	actual, e := m.Native.DNS(live)
	if e != nil {
		return e
	}
	if !winnet.SameDNS(actual, desired) {
		return errors.New("DNS takeover readback differs")
	}
	j.DNS[index].State = "applied"
	return m.Store.Save(j)
}

// Recover marks the transaction stopped before rollback. It resumes planned
// changes after a crash, retains failures, and never overwrites external DNS
// or routes. The caller must stop its core/VPN children before using it.
func (m Manager) Recover() error {
	unlock, e := m.Store.Lock()
	if e != nil {
		return e
	}
	defer unlock()
	j, e := m.load()
	if e != nil {
		return e
	}
	j.Stopping = true
	if e = m.Store.Save(j); e != nil {
		return e
	}
	boot, e := m.Native.BootID()
	if e != nil {
		return e
	}
	var failures []error
	for i := len(j.DNS) - 1; i >= 0; i-- {
		d := j.DNS[i]
		if d.State == "restored" {
			continue
		}
		live, e := m.Native.Adapter(d.Adapter.GUID)
		if e == nil {
			var current winnet.DNSSettings
			current, e = m.Native.DNS(live)
			if e == nil && !winnet.SameDNS(current, d.Before) {
				if !winnet.SameDNS(current, d.After) {
					e = errors.New("DNS changed externally; restoration refused")
				} else {
					e = m.Native.SetDNS(live, d.Before)
				}
			}
			if e == nil {
				current, e = m.Native.DNS(live)
				if e == nil && !winnet.SameDNS(current, d.Before) {
					e = errors.New("DNS restoration readback differs")
				}
			}
		}
		if e != nil {
			failures = append(failures, fmt.Errorf("restore DNS %s: %w", d.Adapter.GUID, e))
			continue
		}
		j.DNS[i].State = "restored"
		if e = m.Store.Save(j); e != nil {
			return e
		}
	}
	for i := len(j.Routes) - 1; i >= 0; i-- {
		if e := m.restoreRoute(&j, i, boot); e != nil {
			failures = append(failures, e)
		}
	}
	if e := m.restoreIsolation(&j, nil, boot); e != nil {
		failures = append(failures, e)
	}
	if e := m.restoreTunnel(&j, nil, boot); e != nil {
		failures = append(failures, e)
	}
	return errors.Join(failures...)
}
