package winstate

import (
	"errors"
	"net/netip"
	"netlaunch/internal/winnet"
	"netlaunch/internal/winwfp"
)

type GuardChange struct {
	Spec  winwfp.Spec `json:"spec"`
	State string      `json:"state"`
}
type PairChange struct {
	Guard    string         `json:"guard"`
	TUN      winnet.Adapter `json:"tun"`
	Capture  RouteChange    `json:"capture"`
	VPN      RouteChange    `json:"vpn"`
	Retiring bool           `json:"retiring"`
}
type GuardBackend interface {
	InspectGuard(winwfp.Spec) (winwfp.Status, error)
	AddGuard(winwfp.Spec) error
	RemoveGuard(winwfp.Spec) error
}

func (m Manager) guardBackend() (GuardBackend, error) {
	n, ok := m.Native.(GuardBackend)
	if !ok {
		return nil, errors.New("WFP backend unavailable")
	}
	return n, nil
}
func pairDone(p PairChange) bool { return p.VPN.State == "restored" && p.Capture.State == "restored" }
func validateIsolation(j Journal) error {
	keys := map[string]winwfp.Spec{}
	for _, g := range j.Guards {
		if g.Spec.Validate() != nil || !validState(g.State) {
			return errors.New("invalid WFP journal")
		}
		if _, ok := keys[g.Spec.Sublayer]; ok {
			return errors.New("duplicate WFP journal key")
		}
		keys[g.Spec.Sublayer] = g.Spec
	}
	for _, p := range j.Pairs {
		g, ok := keys[p.Guard]
		if !ok || !validTunnel(p.TUN) || !validState(p.Capture.State) || !validState(p.VPN.State) || p.Capture.Route.Validate() != nil || p.VPN.Route.Validate() != nil {
			return errors.New("invalid company route pair")
		}
		v, c := p.VPN.Route, p.Capture.Route
		if v.Prefix != c.Prefix || v.NextHop != "0.0.0.0" || c.NextHop != "0.0.0.0" || v.InterfaceIndex != g.Adapter.Index || v.InterfaceLUID != g.Adapter.LUID || c.InterfaceIndex != p.TUN.Index || c.InterfaceLUID != p.TUN.LUID || g.Adapter.Index == p.TUN.Index || g.Adapter.LUID == p.TUN.LUID {
			return errors.New("company route pair identity differs")
		}
	}
	return nil
}
func (m Manager) guardComplete(j Journal, spec winwfp.Spec) error {
	if e := spec.Validate(); e != nil {
		return e
	}
	found := false
	for _, g := range j.Guards {
		if g.State == "applied" && winwfp.Same(g.Spec, spec) {
			found = true
		}
	}
	if !found {
		return errors.New("company guard is not journaled and active")
	}
	if e := m.tunnelAdapter(spec.Adapter); e != nil {
		return e
	}
	n, e := m.guardBackend()
	if e != nil {
		return e
	}
	status, e := n.InspectGuard(spec)
	if e != nil {
		return e
	}
	if !status.Complete() {
		return errors.New("company WFP guard is incomplete")
	}
	return nil
}
func (m Manager) EnsureGuard(spec winwfp.Spec) error {
	if e := spec.Validate(); e != nil {
		return e
	}
	n, e := m.guardBackend()
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
	if e = m.tunnelAdapter(spec.Adapter); e != nil {
		return e
	}
	status, e := n.InspectGuard(spec)
	if e != nil {
		return e
	}
	index := -1
	for i, g := range j.Guards {
		if g.State == "restored" {
			continue
		}
		if winnet.SameAdapter(g.Spec.Adapter, spec.Adapter) || g.Spec.Sublayer == spec.Sublayer {
			if !winwfp.Same(g.Spec, spec) || g.State == "restoring" {
				return errors.New("previous VPN guard needs recovery")
			}
			index = i
		}
	}
	if index < 0 {
		if !status.Empty() {
			return errors.New("WFP rules exist outside this run")
		}
		j.Guards = append(j.Guards, GuardChange{spec, "planned"})
		index = len(j.Guards) - 1
	} else if !status.Empty() && !status.Complete() {
		return errors.New("partial WFP guard needs recovery")
	}
	if e = m.Store.Save(j); e != nil {
		return e
	}
	if e = m.active(j); e != nil {
		return e
	}
	if e = m.tunnelAdapter(spec.Adapter); e != nil {
		return e
	}
	if status.Empty() {
		if e = n.AddGuard(spec); e != nil {
			return e
		}
	}
	status, e = n.InspectGuard(spec)
	if e != nil {
		return e
	}
	if !status.Complete() {
		return errors.New("WFP guard readback differs")
	}
	j.Guards[index].State = "applied"
	return m.Store.Save(j)
}

// companyPair accounts for interface metric as well as route metric. Equal
// cost is not sufficient: unbound application traffic must prefer the core.
func companyPair(spec winwfp.Spec, tun winnet.Adapter, prefix string) (PairChange, error) {
	p := PairChange{Guard: spec.Sublayer, TUN: tun}
	if !validTunnel(tun) || winnet.SameAdapter(tun, spec.Adapter) {
		return p, errors.New("distinct owned TUN required")
	}
	metric := uint64(1)
	if tun.Metric >= spec.Adapter.Metric {
		metric = uint64(tun.Metric) - uint64(spec.Adapter.Metric) + 1
	}
	if metric > uint64(^uint32(0)) {
		return p, errors.New("company route metric overflow")
	}
	c, e := winnet.NewRoute(tun, prefix, "0.0.0.0", 0)
	if e != nil {
		return p, e
	}
	v, e := winnet.NewRoute(spec.Adapter, prefix, "0.0.0.0", uint32(metric))
	if e != nil {
		return p, e
	}
	p.Capture = RouteChange{c, "planned"}
	p.VPN = RouteChange{v, "planned"}
	return p, nil
}
func (m Manager) pairScope(p PairChange, spec winwfp.Spec) error {
	if e := m.tunnelAdapter(p.TUN); e != nil {
		return e
	}
	tun, e := m.Native.Adapter(p.TUN.GUID)
	if e != nil {
		return e
	}
	vpn, e := m.Native.Adapter(spec.Adapter.GUID)
	if e != nil {
		return e
	}
	if !winnet.SameAdapter(vpn, spec.Adapter) || !tun.Up || !vpn.Up {
		return errors.New("company adapter changed or down")
	}
	if uint64(tun.Metric)+uint64(p.Capture.Route.Metric) >= uint64(vpn.Metric)+uint64(p.VPN.Route.Metric) {
		return errors.New("company capture no longer has lower effective metric")
	}
	return nil
}
func (m Manager) applyPairRoute(j *Journal, r *RouteChange) error {
	actual, e := m.Native.Lookup(r.Route)
	if e != nil {
		return e
	}
	if actual != nil {
		if !winnet.OwnedEqual(*actual, r.Route) {
			return errors.New("company route changed externally")
		}
		// Renewal must still re-read native ownership, but an already committed
		// route has no new recovery intent to flush to disk.
		if r.State == "applied" {
			return nil
		}
	} else {
		if r.State != "planned" {
			return errors.New("applied company route disappeared")
		}
		created, e := m.Native.Add(r.Route)
		if e != nil {
			return e
		}
		if !winnet.OwnedEqual(created, r.Route) {
			return errors.New("company route readback differs")
		}
	}
	r.State = "applied"
	return m.Store.Save(*j)
}
func (m Manager) EnsureCompanyRoute(spec winwfp.Spec, tun winnet.Adapter, prefix string) error {
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
	if e = m.guardComplete(j, spec); e != nil {
		return e
	}
	live, e := m.Native.Adapter(tun.GUID)
	if e != nil {
		return e
	}
	if !winnet.SameAdapter(tun, live) {
		return errors.New("capture adapter changed")
	}
	vpn, e := m.Native.Adapter(spec.Adapter.GUID)
	if e != nil {
		return e
	}
	fresh := spec
	fresh.Adapter = vpn
	wanted, e := companyPair(fresh, live, prefix)
	if e != nil {
		return e
	}
	index := -1
	for i, p := range j.Pairs {
		if pairDone(p) || p.Guard != spec.Sublayer || p.VPN.Route.Prefix != prefix {
			continue
		}
		if p.Retiring || !winnet.SameAdapter(p.TUN, tun) {
			return errors.New("previous company pair needs recovery")
		}
		index = i
	}
	if index < 0 {
		for _, r := range []winnet.Route{wanted.Capture.Route, wanted.VPN.Route} {
			actual, e := m.Native.Lookup(r)
			if e != nil {
				return e
			}
			if actual != nil {
				return errors.New("company route exists outside this run")
			}
		}
		j.Pairs = append(j.Pairs, wanted)
		index = len(j.Pairs) - 1
		if e = m.Store.Save(j); e != nil {
			return e
		}
	}
	p := &j.Pairs[index]
	check := func() error {
		if e := m.active(j); e != nil {
			return e
		}
		if e := m.guardComplete(j, spec); e != nil {
			return e
		}
		return m.pairScope(*p, spec)
	}
	if p.Capture.State == "applied" && p.VPN.State == "applied" {
		// No native mutation is needed. Recheck both owned rows and effective
		// metrics between fresh guard checks, without the intermediate barriers
		// needed when installing capture and then granting a new VPN route.
		if e = m.pairScope(*p, spec); e != nil {
			return e
		}
		for _, r := range []winnet.Route{p.Capture.Route, p.VPN.Route} {
			actual, err := m.Native.Lookup(r)
			if err != nil {
				return err
			}
			if actual == nil || !winnet.OwnedEqual(*actual, r) {
				return errors.New("company route pair is no longer owned")
			}
		}
		return check()
	}
	if e = check(); e != nil {
		return e
	}
	if e = m.applyPairRoute(&j, &p.Capture); e != nil {
		return e
	}
	if e = check(); e != nil {
		return e
	}
	// Read the capture back again immediately before granting the VPN route.
	actual, e := m.Native.Lookup(p.Capture.Route)
	if e != nil {
		return e
	}
	if actual == nil || !winnet.OwnedEqual(*actual, p.Capture.Route) {
		return errors.New("company capture disappeared before VPN route")
	}
	if e = m.applyPairRoute(&j, &p.VPN); e != nil {
		return e
	}
	return check()
}

// CheckCompanyAddress is called before and after socket connection, including
// bootstrap DNS. No cached WFP status can authorize a newly connected socket.
func (m Manager) CheckCompanyAddress(spec winwfp.Spec, ip string) error {
	a, e := netip.ParseAddr(ip)
	if e != nil || !a.Is4() {
		return errors.New("company IPv4 required")
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
	if e = m.guardComplete(j, spec); e != nil {
		return e
	}
	for _, p := range j.Pairs {
		prefix, _ := netip.ParsePrefix(p.VPN.Route.Prefix)
		if p.Guard != spec.Sublayer || p.Retiring || p.VPN.State != "applied" || p.Capture.State != "applied" || !prefix.Contains(a) {
			continue
		}
		if e = m.pairScope(p, spec); e != nil {
			return e
		}
		for _, r := range []winnet.Route{p.Capture.Route, p.VPN.Route} {
			actual, e := m.Native.Lookup(r)
			if e != nil {
				return e
			}
			if actual == nil || !winnet.OwnedEqual(*actual, r) {
				return errors.New("company route pair is no longer owned")
			}
		}
		return nil
	}
	return errors.New("no active company route pair covers address")
}

func (m Manager) restorePair(j *Journal, i int, boot string) error {
	p := &j.Pairs[i]
	if pairDone(*p) {
		return nil
	}
	p.Retiring = true
	if e := m.Store.Save(*j); e != nil {
		return e
	}
	if e := m.restoreRouteChange(j, &p.VPN, boot); e != nil {
		return e
	}
	// A failed VPN deletion must leave its capture in place.
	return m.restoreRouteChange(j, &p.Capture, boot)
}
func (m Manager) RemoveCompanyRoute(spec winwfp.Spec, prefix string) error {
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
	for i, p := range j.Pairs {
		if p.Guard == spec.Sublayer && p.VPN.Route.Prefix == prefix && !pairDone(p) {
			return m.restorePair(&j, i, j.BootID)
		}
	}
	return nil
}
func (m Manager) restoreIsolation(j *Journal, only *winnet.Adapter, boot string) error {
	var failures []error
	for i, p := range j.Pairs {
		if only != nil && (p.VPN.Route.InterfaceLUID != only.LUID || p.VPN.Route.InterfaceIndex != only.Index) {
			continue
		}
		if e := m.restorePair(j, i, boot); e != nil {
			failures = append(failures, e)
		}
	}
	for i, g := range j.Guards {
		if g.State == "restored" || (only != nil && !winnet.SameAdapter(*only, g.Spec.Adapter)) {
			continue
		}
		pending := false
		for _, p := range j.Pairs {
			if p.Guard == g.Spec.Sublayer && !pairDone(p) {
				pending = true
			}
		}
		for _, r := range j.Routes {
			if r.State != "restored" && r.Route.InterfaceLUID == g.Spec.Adapter.LUID && r.Route.InterfaceIndex == g.Spec.Adapter.Index {
				pending = true
			}
		}
		if pending {
			failures = append(failures, errors.New("WFP protection retained while company routes remain"))
			continue
		}
		n, e := m.guardBackend()
		if e != nil {
			failures = append(failures, e)
			continue
		}
		j.Guards[i].State = "restoring"
		if e = m.Store.Save(*j); e != nil {
			j.Guards[i].State = g.State
			failures = append(failures, e)
			continue
		}
		status, e := n.InspectGuard(g.Spec)
		if e == nil && !status.Empty() {
			if boot != j.BootID {
				e = errors.New("WFP rules survived boot change; ownership unproven")
			} else {
				e = n.RemoveGuard(g.Spec)
			}
			if e == nil {
				status, e = n.InspectGuard(g.Spec)
				if e == nil && !status.Empty() {
					e = errors.New("owned WFP guard remains")
				}
			}
		}
		if e != nil {
			failures = append(failures, e)
			continue
		}
		j.Guards[i].State = "restored"
		if e = m.Store.Save(*j); e != nil {
			j.Guards[i].State = "restoring"
			failures = append(failures, e)
		}
	}
	return errors.Join(failures...)
}

func (m Manager) CheckCompanyGuard(spec winwfp.Spec) error {
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
	return m.guardComplete(j, spec)
}
