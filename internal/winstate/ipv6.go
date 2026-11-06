package winstate

import (
	"errors"
	"netlaunch/internal/winwfp"
)

type IPv6GuardChange struct {
	Spec  winwfp.IPv6Spec `json:"spec"`
	State string          `json:"state"`
}
type IPv6Backend interface {
	InspectIPv6(winwfp.IPv6Spec) (winwfp.IPv6Status, error)
	AddIPv6(winwfp.IPv6Spec) error
	RemoveIPv6(winwfp.IPv6Spec) error
}

func validateIPv6(j Journal) error {
	seen := map[string]bool{}
	for _, g := range j.IPv6Guards {
		if !validState(g.State) || g.Spec.Validate() != nil {
			return errors.New("invalid global IPv6 journal")
		}
		for _, k := range []string{g.Spec.Provider, g.Spec.Sublayer, g.Spec.Outbound, g.Spec.Forward} {
			if seen[k] {
				return errors.New("duplicate global IPv6 journal key")
			}
			seen[k] = true
		}
	}
	return nil
}
func (m Manager) EnsureIPv6(spec winwfp.IPv6Spec) error {
	if e := spec.Validate(); e != nil {
		return e
	}
	n, ok := m.Native.(IPv6Backend)
	if !ok {
		return errors.New("global IPv6 backend unavailable")
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
	i := -1
	for index, g := range j.IPv6Guards {
		if g.Spec.Provider == spec.Provider {
			if g.Spec != spec || g.State == "restoring" {
				return errors.New("global IPv6 intent changed")
			}
			i = index
		}
	}
	st, e := n.InspectIPv6(spec)
	if e != nil {
		return e
	}
	if i < 0 {
		if !st.Empty() {
			return errors.New("unowned global IPv6 resource exists")
		}
		j.IPv6Guards = append(j.IPv6Guards, IPv6GuardChange{spec, "planned"})
		i = len(j.IPv6Guards) - 1
		if e = m.Store.Save(j); e != nil {
			return e
		}
	}
	if j.IPv6Guards[i].State == "applied" {
		if !st.Complete() {
			return errors.New("global IPv6 guard lost protection")
		}
		return nil
	}
	if st.Empty() {
		if e = n.AddIPv6(spec); e != nil {
			return e
		}
	} else if !st.Complete() {
		return errors.New("partial global IPv6 protection")
	}
	st, e = n.InspectIPv6(spec)
	if e != nil {
		return e
	}
	if !st.Complete() {
		return errors.New("global IPv6 readback incomplete")
	}
	j.IPv6Guards[i].State = "applied"
	return m.Store.Save(j)
}
func (m Manager) CheckIPv6(spec winwfp.IPv6Spec) error {
	n, ok := m.Native.(IPv6Backend)
	if !ok {
		return errors.New("global IPv6 backend unavailable")
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
	found := false
	for _, g := range j.IPv6Guards {
		found = found || (g.Spec == spec && g.State == "applied")
	}
	if !found {
		return errors.New("global IPv6 guard not committed")
	}
	st, e := n.InspectIPv6(spec)
	if e != nil {
		return e
	}
	if !st.Complete() {
		return errors.New("global IPv6 guard not complete")
	}
	return nil
}
func (m Manager) restoreIPv6(j *Journal) error {
	if len(j.IPv6Guards) == 0 {
		return nil
	}
	n, ok := m.Native.(IPv6Backend)
	if !ok {
		return errors.New("global IPv6 recovery backend unavailable")
	}
	for i := len(j.IPv6Guards) - 1; i >= 0; i-- {
		g := j.IPv6Guards[i]
		if g.State == "restored" {
			continue
		}
		j.IPv6Guards[i].State = "restoring"
		if e := m.Store.Save(*j); e != nil {
			return e
		}
		st, e := n.InspectIPv6(g.Spec)
		if e != nil {
			return e
		}
		if !st.Empty() {
			if e = n.RemoveIPv6(g.Spec); e != nil {
				return e
			}
		}
		st, e = n.InspectIPv6(g.Spec)
		if e != nil {
			return e
		}
		if !st.Empty() {
			return errors.New("global IPv6 removal readback incomplete")
		}
		j.IPv6Guards[i].State = "restored"
		if e = m.Store.Save(*j); e != nil {
			return e
		}
	}
	return nil
}

func (m Manager) ReleaseIPv6() error {
	unlock, e := m.Store.Lock()
	if e != nil {
		return e
	}
	defer unlock()
	j, e := m.load()
	if e != nil {
		return e
	}
	check := j
	check.IPv6Guards = nil
	if e = CheckRecovered(check); e != nil {
		return e
	}
	return m.restoreIPv6(&j)
}
