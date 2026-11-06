//go:build windows

package engine

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netlaunch/internal/auth"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/winnet"
	"netlaunch/internal/winstate"
	"netlaunch/internal/winwfp"
)

type ServiceProcessProof struct {
	Role  string `json:"role"`
	PID   int    `json:"pid"`
	Birth string `json:"birth"`
	State string `json:"state"`
}
type ServiceRecoveryProof struct {
	Clean                   bool                     `json:"clean"`
	PreparedOnly            bool                     `json:"prepared_only"`
	IdentityMappingComplete bool                     `json:"identity_mapping_complete"`
	AdaptersAbsent          bool                     `json:"adapters_absent"`
	ProcessesGone           bool                     `json:"processes_gone"`
	NetworkRestored         bool                     `json:"network_restored"`
	WFPAbsent               bool                     `json:"wfp_absent"`
	IPv6Absent              bool                     `json:"ipv6_absent"`
	Adapters                []winnet.AdapterPresence `json:"adapters"`
	Processes               []ServiceProcessProof    `json:"processes"`
	Errors                  []string                 `json:"errors"`
	StartedAt               time.Time                `json:"started_at"`
	FinishedAt              time.Time                `json:"finished_at"`
}
type ServiceStatusResult struct {
	RunID         string                `json:"run_id"`
	Status        Status                `json:"status"`
	Restored      bool                  `json:"restored"`
	Proof         *ServiceRecoveryProof `json:"proof,omitempty"`
	IPv6State     string                `json:"ipv6_state"`
	IPv6Blocked   bool                  `json:"ipv6_blocked"`
	IPv6CheckedAt time.Time             `json:"ipv6_checked_at"`
	AuthNetwork   *ServiceAuthNetwork   `json:"auth_network,omitempty"`
}
type ServiceAuthNetwork struct {
	GUID       string `json:"guid"`
	LUID       uint64 `json:"luid"`
	Index      uint32 `json:"index"`
	Address    string `json:"address"`
	Gateway    string `json:"gateway"`
	Generation string `json:"generation"`
}
type serviceProofNative struct {
	presence func(winnet.Adapter) (winnet.AdapterPresence, error)
	process  func(int) (platform.Identity, error)
	route    func(winnet.Route) (*winnet.Route, error)
	dns      func(winnet.Adapter, bool) (winnet.DNSSettings, error)
	guard    func(winwfp.Spec) (winwfp.Status, error)
	ipv6     func(winwfp.IPv6Spec) (winwfp.IPv6Status, error)
}

func nativeServiceProof() serviceProofNative {
	return serviceProofNative{winnet.ObserveAdapterPresence, platform.Process, winnet.Lookup, winnet.ConfiguredDNSFamily, winwfp.Inspect, winwfp.InspectIPv6}
}
func ownedAdapterIdentity(a winnet.Adapter) winnet.Adapter {
	return winnet.Adapter{GUID: a.GUID, Name: a.Name, Index: a.Index, LUID: a.LUID, Type: a.Type, Hardware: a.Hardware}
}
func bindOwnedAdapterIntent(s *State, role string, a winnet.Adapter) error {
	for i := len(s.Windows.AdapterIntents) - 1; i >= 0; i-- {
		intent := &s.Windows.AdapterIntents[i]
		if intent.Role != role || intent.Name != a.Name {
			continue
		}
		if intent.Owner.PID < 2 || intent.Owner.Birth == "" || intent.Owner.OwnerSID != "S-1-5-18" {
			return errors.New("owned adapter process mapping incomplete")
		}
		if intent.Adapter != nil && !winnet.SameAdapter(*intent.Adapter, a) {
			return errors.New("owned adapter mapping changed")
		}
		frozen := ownedAdapterIdentity(a)
		intent.Adapter = &frozen
		return nil
	}
	return errors.New("owned adapter creation intent missing")
}
func serviceOwnedAdapters(s State, j winstate.Journal) ([]winnet.Adapter, error) {
	if s.Windows == nil {
		return nil, errors.New("Windows state missing")
	}
	var result []winnet.Adapter
	add := func(a winnet.Adapter) error {
		if a.GUID == "" || a.Index == 0 || a.LUID == 0 || a.Type != 53 || a.Hardware {
			return errors.New("complete owned adapter mapping missing")
		}
		for _, old := range result {
			if strings.EqualFold(old.GUID, a.GUID) {
				if !winnet.SameAdapter(old, a) || old.Name != a.Name {
					return errors.New("owned adapter identity conflict")
				}
				return nil
			}
		}
		result = append(result, ownedAdapterIdentity(a))
		return nil
	}
	for _, intent := range s.Windows.AdapterIntents {
		if intent.Adapter == nil || intent.Name != intent.Adapter.Name || (intent.Role != "core" && intent.Role != "vpn") {
			return nil, errors.New("adapter created without a complete frozen identity")
		}
		if err := add(*intent.Adapter); err != nil {
			return nil, err
		}
	}
	for _, child := range s.Children {
		if child.Role != "core" && child.Role != "vpn" {
			return nil, errors.New("unrecognized owned child role")
		}
		mapped := false
		for _, intent := range s.Windows.AdapterIntents {
			mapped = mapped || child.Native != nil && sameProcess(intent.Owner, *child.Native) && intent.Role == child.Role
		}
		if !mapped {
			return nil, errors.New("released child has no durable adapter intent")
		}
	}
	for _, g := range j.Guards {
		if err := add(g.Spec.Adapter); err != nil {
			return nil, err
		}
	}
	for _, p := range j.Pairs {
		if err := add(p.TUN); err != nil {
			return nil, err
		}
	}
	for _, a := range j.Addresses {
		if err := add(a.Adapter); err != nil {
			return nil, err
		}
	}
	for _, a := range j.MTU {
		if err := add(a.Adapter); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func observeServiceRecovery(s State, j winstate.Journal, n serviceProofNative) ServiceRecoveryProof {
	p := ServiceRecoveryProof{StartedAt: time.Now(), Adapters: []winnet.AdapterPresence{}, Processes: []ServiceProcessProof{}, Errors: []string{}, NetworkRestored: true, WFPAbsent: true, IPv6Absent: true, AdaptersAbsent: true, ProcessesGone: true}
	fail := func(code string) { p.Errors = append(p.Errors, code) }
	adapters, err := serviceOwnedAdapters(s, j)
	p.IdentityMappingComplete = err == nil
	if err != nil {
		p.AdaptersAbsent = false
		fail("owned_adapter_mapping_incomplete")
	}
	for _, a := range adapters {
		o, err := n.presence(a)
		p.Adapters = append(p.Adapters, o)
		if err != nil || o.State != "absent" {
			p.AdaptersAbsent = false
			fail("owned_adapter_not_absent")
		}
	}
	roles := []struct {
		role string
		id   platform.Identity
	}{{"coordinator", s.Runner}, {"watchdog", s.Watcher}}
	for _, c := range s.Children {
		if c.Native == nil {
			p.ProcessesGone = false
			fail("owned_process_identity_incomplete")
			continue
		}
		roles = append(roles, struct {
			role string
			id   platform.Identity
		}{c.Role, *c.Native})
	}
	for _, role := range roles {
		id := role.id
		if id.PID == 0 {
			if role.role == "watchdog" && len(s.Children) == 0 {
				continue
			}
			p.ProcessesGone = false
			fail("owned_process_identity_incomplete")
			continue
		}
		item := ServiceProcessProof{Role: role.role, PID: id.PID, Birth: id.Birth, State: "unknown"}
		if id.PID < 2 || id.Birth == "" || id.Executable == "" || id.OwnerSID != "S-1-5-18" {
			p.ProcessesGone = false
			fail("owned_process_identity_incomplete")
		} else {
			actual, err := n.process(id.PID)
			if err != nil {
				p.ProcessesGone = false
				fail("owned_process_query_unknown")
			} else if actual.PID == 0 || actual.Birth != "" && actual.Birth != id.Birth {
				item.State = "absent"
			} else {
				item.State = "present"
				p.ProcessesGone = false
				fail("owned_process_still_present")
			}
		}
		p.Processes = append(p.Processes, item)
	}
	if winstate.CheckRecovered(j) != nil {
		p.NetworkRestored = false
		fail("network_journal_incomplete")
	}
	routes := append([]winstate.RouteChange(nil), j.Routes...)
	for _, pair := range j.Pairs {
		routes = append(routes, pair.VPN, pair.Capture)
	}
	for _, r := range routes {
		actual, err := n.route(r.Route)
		if err != nil || actual != nil {
			p.NetworkRestored = false
			fail("owned_route_not_absent")
		}
	}
	for _, d := range j.DNS {
		actual, err := n.dns(d.Adapter, d.Before.IPv6)
		if err != nil || !winnet.SameDNS(actual, d.Before) {
			p.NetworkRestored = false
			fail("physical_dns_not_restored")
		}
	}
	// Address/MTU entries are restricted by the journal validator to the exact
	// owned virtual adapters. Their strict absence proves those resources gone.
	if (len(j.Addresses) > 0 || len(j.MTU) > 0) && !p.AdaptersAbsent {
		p.NetworkRestored = false
		fail("owned_tunnel_resources_unverified")
	}
	for _, g := range j.Guards {
		actual, err := n.guard(g.Spec)
		if err != nil || !actual.Empty() {
			p.WFPAbsent = false
			fail("owned_wfp_not_absent")
		}
	}
	for _, g := range j.IPv6Guards {
		actual, err := n.ipv6(g.Spec)
		if err != nil || !actual.Empty() {
			p.IPv6Absent = false
			fail("owned_ipv6_not_absent")
		}
	}
	p.FinishedAt = time.Now()
	if p.FinishedAt.Sub(p.StartedAt) > 10*time.Second {
		fail("strict_readback_deadline_exceeded")
	}
	p.Clean = s.Phase == "stopped" && !s.TakeoverActive && p.IdentityMappingComplete && p.AdaptersAbsent && p.ProcessesGone && p.NetworkRestored && p.WFPAbsent && p.IPv6Absent && len(p.Errors) == 0
	return p
}

func requireServiceAdaptersAbsent(s State, j winstate.Journal) error {
	adapters, err := serviceOwnedAdapters(s, j)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		complete := true
		for _, a := range adapters {
			o, err := winnet.ObserveAdapterPresence(a)
			if err != nil {
				return err
			}
			if !time.Now().Before(deadline) {
				return errors.New("strict adapter recovery deadline reached")
			}
			if o.State != "absent" {
				complete = false
				if o.State != "present" {
					return errors.New("strict adapter presence unknown")
				}
			}
		}
		if complete {
			return nil
		}
		if !time.Now().Before(deadline) {
			return errors.New("owned adapter remains present")
		}
		time.Sleep(min(100*time.Millisecond, time.Until(deadline)))
	}
}
func servicePreparedOnly(run string) (bool, error) {
	files, id, err := winFiles(run)
	if err != nil {
		return false, err
	}
	_, err = os.Lstat(filepath.Join(files.Root, id))
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}
func ServiceStatus(r ServiceRunReference) (ServiceStatusResult, error) {
	run, _, err := ServiceManifest(r)
	if err != nil {
		return ServiceStatusResult{}, err
	}
	prepared, err := servicePreparedOnly(run)
	if err != nil {
		return ServiceStatusResult{}, err
	}
	if prepared {
		return ServiceStatusResult{RunID: r.RunID, Status: Status{Phase: "prepared", Lifecycle: "prepared", Updated: time.Now()}, IPv6State: "unknown"}, nil
	}
	s, err := load(run)
	if err != nil {
		return ServiceStatusResult{}, err
	}
	result := ServiceStatusResult{RunID: r.RunID, Status: publicStatus(s, time.Now()), IPv6State: "unknown"}
	if s.TakeoverActive && s.Windows.IPv6Guard != nil && s.Phase != "stopping" && s.Phase != "stopped" && s.Phase != "recovery_failed" {
		if m, managerErr := networkManager(run); managerErr == nil {
			if checkErr := m.CheckIPv6(*s.Windows.IPv6Guard); checkErr == nil {
				result.IPv6State = "blocked"
				result.IPv6Blocked = true
			}
		}
		result.IPv6CheckedAt = time.Now()
	}
	if result.IPv6Blocked {
		actual, err := winnet.Discover()
		if err == nil && winnet.SameAdapter(actual.Adapter, s.Windows.Physical.Adapter) && actual.Address == s.Windows.Physical.Address && actual.Gateway == s.Windows.Physical.Gateway {
			plan := &ServiceAuthNetwork{GUID: actual.Adapter.GUID, LUID: actual.Adapter.LUID, Index: actual.Adapter.Index, Address: actual.Address, Gateway: actual.Gateway}
			plan.Generation = serviceHash(struct {
				RunRef  string
				Epoch   uint64
				Network ServiceAuthNetwork
			}{s.Manifest.Service.RunRef, s.Windows.Epoch, *plan})
			result.AuthNetwork = plan
		}
	}
	if s.Phase == "stopped" || s.Phase == "recovery_failed" {
		m, err := networkManager(run)
		if err != nil {
			return result, err
		}
		j, err := m.Store.Load()
		if err != nil {
			return result, err
		}
		proof := observeServiceRecovery(s, j, nativeServiceProof())
		result.Proof = &proof
		result.Restored = proof.Clean
		if proof.Clean {
			result.IPv6State = "restored"
			result.IPv6CheckedAt = proof.FinishedAt
		}
	}
	return result, nil
}
func RecoverServiceRun(r ServiceRunReference) (ServiceRecoveryProof, error) {
	run, _, err := ServiceManifest(r)
	if err != nil {
		return ServiceRecoveryProof{}, err
	}
	prepared, err := servicePreparedOnly(run)
	if err != nil {
		return ServiceRecoveryProof{}, err
	}
	if prepared {
		for _, name := range []string{"auth.json", "auth-refresh.json"} {
			if err := os.Remove(filepath.Join(run, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return ServiceRecoveryProof{}, err
			}
		}
		now := time.Now()
		p := ServiceRecoveryProof{Clean: true, PreparedOnly: true, IdentityMappingComplete: true, AdaptersAbsent: true, ProcessesGone: true, NetworkRestored: true, WFPAbsent: true, IPv6Absent: true, Adapters: []winnet.AdapterPresence{}, Processes: []ServiceProcessProof{}, Errors: []string{}, StartedAt: now, FinishedAt: now}
		return p, nil
	}
	if err = recoverRun(run, "service_stop_restore"); err != nil {
		originalErr := err
		if s, readErr := load(run); readErr == nil {
			if m, managerErr := networkManager(run); managerErr == nil {
				if j, journalErr := m.Store.Load(); journalErr == nil {
					return observeServiceRecovery(s, j, nativeServiceProof()), originalErr
				}
			}
		}
		return ServiceRecoveryProof{Errors: []string{"service_recovery_failed"}}, originalErr
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		s, err := load(run)
		if err != nil {
			return ServiceRecoveryProof{}, err
		}
		m, err := networkManager(run)
		if err != nil {
			return ServiceRecoveryProof{}, err
		}
		j, err := m.Store.Load()
		if err != nil {
			return ServiceRecoveryProof{}, err
		}
		p := observeServiceRecovery(s, j, nativeServiceProof())
		if !time.Now().Before(deadline) {
			p.Clean = false
			p.Errors = append(p.Errors, "strict_readback_deadline_exceeded")
			return p, errors.New("strict service recovery readback deadline reached")
		}
		if p.Clean {
			if err = winWrite(run, "service-recovery-proof.json", p); err != nil {
				return p, err
			}
			for _, name := range []string{"auth.json", "auth-refresh.json"} {
				_ = os.Remove(filepath.Join(run, name))
			}
			return p, nil
		}
		if !p.IdentityMappingComplete || !p.NetworkRestored || !p.WFPAbsent || !p.IPv6Absent {
			return p, errors.New("service recovery proof incomplete")
		}
		time.Sleep(min(100*time.Millisecond, time.Until(deadline)))
	}
}
func SetServiceChannels(r ServiceRunReference, intent policy.ChannelIntent) error {
	run, _, err := ServiceManifest(r)
	if err != nil {
		return err
	}
	return SetChannels(run, intent)
}

func RefreshServiceAuth(r ServiceRunReference, session auth.Session) error {
	run, m, err := ServiceManifest(r)
	if err != nil {
		return err
	}
	if !session.ValidAt(time.Now()) {
		return errors.New("fresh service authentication required")
	}
	value, err := auth.EncodeRuntime(m.Config.VPN, session)
	if err != nil {
		return err
	}
	return update(run, func(s *State) error {
		if err := guard(run, s); err != nil {
			return err
		}
		return securefile.Write(filepath.Join(run, "auth-refresh.json"), value)
	})
}
