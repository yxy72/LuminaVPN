//go:build windows

package main

import (
	"context"
	"errors"
	"net"
	"netlaunch/internal/securefile"
	"netlaunch/internal/socketbind"
	"netlaunch/internal/winnet"
	"netlaunch/internal/winstate"
	"netlaunch/internal/winwfp"
	"os"
	"path/filepath"
	"time"
)

type transition struct {
	Capture, VPN string
	Retiring     bool
}
type probeStore struct{ winstate.NativeStorage }

func validPairFault(fault string) bool {
	switch fault {
	case "pair-planned", "pair-capture-applied", "pair-vpn-applied", "pair-retiring", "pair-vpn-restored":
		return true
	}
	return false
}

func pairFaultMatches(fault string, pair winstate.PairChange) bool {
	switch fault {
	case "pair-planned":
		return !pair.Retiring && pair.Capture.State == "planned" && pair.VPN.State == "planned"
	case "pair-capture-applied":
		return !pair.Retiring && pair.Capture.State == "applied" && pair.VPN.State == "planned"
	case "pair-vpn-applied":
		return !pair.Retiring && pair.Capture.State == "applied" && pair.VPN.State == "applied"
	case "pair-retiring":
		return pair.Retiring && pair.Capture.State == "applied" && pair.VPN.State == "applied"
	case "pair-vpn-restored":
		return pair.Retiring && pair.Capture.State == "applied" && pair.VPN.State == "restored"
	}
	return false
}

func (s probeStore) Save(j winstate.Journal) error {
	return saveProbeJournalWithDiagnostics(j, s.NativeStorage.Save, s.saveTransitions, func(err error) {
		recordProbeDiagnosticFailure(s.Files, s.RunID, err)
	})
}

func appendProbeTransitions(j winstate.Journal, load func() ([]transition, error), save func([]transition) error) error {
	if len(j.Pairs) == 0 {
		return nil
	}
	events, e := load()
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if len(events) > 4096 {
		return errors.New("probe transition limit")
	}
	for _, p := range j.Pairs {
		events = append(events, transition{p.Capture.State, p.VPN.State, p.Retiring})
	}
	return save(events)
}

func (s probeStore) saveTransitions(j winstate.Journal) error {
	if len(j.Pairs) == 0 {
		return nil
	}
	if e := appendProbeTransitions(j, func() ([]transition, error) {
		var events []transition
		err := read(s.Files, s.RunID, "probe-transitions.json", &events)
		return events, err
	}, func(events []transition) error {
		return s.Files.Write(filepath.Join(s.RunID, "probe-transitions.json"), events)
	}); e != nil {
		return e
	}
	if j.Stopping {
		return nil // Recovery does not execute owner fault-injection hooks.
	}
	var p plan
	if e := read(s.Files, s.RunID, "probe-plan.json", &p); e != nil {
		return e
	}
	if p.Owner.PID == os.Getpid() && validPairFault(p.Fault) {
		for _, pair := range j.Pairs {
			if pairFaultMatches(p.Fault, pair) {
				if e := s.Files.Write(filepath.Join(s.RunID, "probe-fault-triggered.json"), map[string]any{"fault": p.Fault, "time": time.Now()}); e != nil {
					return e
				}
				os.Exit(42) // Deliberate abrupt exit: no deferred cleanup.
			}
		}
	}
	return nil
}

func secondAdapter(files securefile.AdminStore, id string) (winnet.Adapter, error) {
	return readyProbeAdapter(files, id, "-tun")
}

func exercisePair(files securefile.AdminStore, id string, vpn winnet.Adapter) error {
	tun, e := secondAdapter(files, id)
	if e != nil {
		return e
	}
	m := manager(files, id)
	status := map[string]any{"stage": "pair"}
	record := func(key string, err error) error {
		status[key] = err == nil
		if err != nil {
			status["error"] = err.Error()
		}
		if e := files.Write(filepath.Join(id, "probe-native.json"), status); e != nil {
			return e
		}
		return err
	}
	rows, e := winnet.Routes()
	if e != nil {
		return e
	}
	for _, r := range rows {
		if r.Prefix == "192.0.2.1/32" || r.Prefix == "192.0.2.2/32" || r.Prefix == "192.0.2.3/32" {
			return errors.New("fixture route conflict")
		}
	}
	vpnAddress, e := m.EnsureVPNAddress(vpn, "192.0.2.1")
	if e != nil {
		return record("vpn_address", e)
	}
	tunAddress, e := m.EnsureVPNAddress(tun, "192.0.2.3")
	if e != nil {
		return record("tun_address", e)
	}
	for _, address := range []winnet.Address{vpnAddress, tunAddress} {
		until := time.Now().Add(5 * time.Second)
		for {
			e = winnet.AddressReady(address)
			if e == nil {
				break
			}
			if time.Now().After(until) {
				return record("addresses_ready", e)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	if e = record("addresses_ready", nil); e != nil {
		return e
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	guard, e := winwfp.Prepare(vpn, exe)
	if e != nil {
		return e
	}
	if e = record("guard", m.EnsureGuard(guard)); e != nil {
		return e
	}
	prefix := "192.0.2.2/32"
	conflict, e := winnet.NewRoute(tun, prefix, "0.0.0.0", 0)
	if e != nil {
		return e
	}
	if e = m.EnsureRoute(conflict); e != nil {
		return e
	}
	if m.EnsureCompanyRoute(guard, tun, prefix) == nil {
		return record("existing_route_rejected", errors.New("pair adopted an existing route"))
	}
	if e = record("existing_route_rejected", nil); e != nil {
		return e
	}
	if e = m.RemoveRoute(conflict); e != nil {
		return e
	}
	if e = record("pair_installed", m.EnsureCompanyRoute(guard, tun, prefix)); e != nil {
		return e
	}
	if e = record("pair_authorized", m.CheckCompanyAddress(guard, "192.0.2.2")); e != nil {
		return e
	}
	j, e := m.Store.Load()
	if e != nil {
		return e
	}
	if len(j.Pairs) != 1 {
		return errors.New("unexpected pair journal")
	}
	pair := j.Pairs[0]
	if uint64(tun.Metric)+uint64(pair.Capture.Route.Metric) >= uint64(vpn.Metric)+uint64(pair.VPN.Route.Metric) {
		return record("metric_order", errors.New("capture not preferred"))
	}
	if e = record("metric_order", nil); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, e := socketbind.DialChecked(ctx, vpn.Index, "192.0.2.1", "192.0.2.2:18443", func() error { return m.CheckCompanyAddress(guard, "192.0.2.2") })
	if e != nil {
		return record("bound_company_tcp", e)
	}
	c.Close()
	if e = record("bound_company_tcp", nil); e != nil {
		return e
	}
	c, e = net.DialTimeout("tcp4", "192.0.2.2:18443", 3*time.Second)
	if e != nil {
		return record("unbound_capture_tcp", e)
	}
	source := c.LocalAddr().(*net.TCPAddr).IP.String()
	c.Close()
	if source != "192.0.2.3" {
		return record("unbound_capture_tcp", errors.New("unbound TCP missed capture adapter"))
	}
	if e = record("unbound_capture_tcp", nil); e != nil {
		return e
	}
	time.Sleep(200 * time.Millisecond)
	for _, role := range []string{"", "-tun"} {
		var counts map[string]int
		if e = read(files, id, "probe-packets"+role+".json", &counts); e != nil {
			return e
		}
		if counts["tcp_18443"] < 1 {
			return errors.New("missing paired packet evidence")
		}
	}
	if e = record("withdraw_pair", m.RemoveCompanyRoute(guard, prefix)); e != nil {
		return e
	}
	for _, r := range []winnet.Route{pair.VPN.Route, pair.Capture.Route} {
		got, e := winnet.Lookup(r)
		if e != nil {
			return e
		}
		if got != nil {
			return errors.New("withdrawn pair remains")
		}
	}
	if m.CheckCompanyAddress(guard, "192.0.2.2") == nil {
		return errors.New("withdrawn pair still authorized")
	}
	if e = record("withdrawn_denied_guard_retained", m.CheckCompanyGuard(guard)); e != nil {
		return e
	}
	var events []transition
	if e = read(files, id, "probe-transitions.json", &events); e != nil {
		return e
	}
	for _, event := range events {
		if event.Capture == "restoring" && event.VPN != "restored" {
			return errors.New("capture retired before company route")
		}
		if !event.Retiring && event.VPN == "applied" && event.Capture != "applied" {
			return errors.New("company granted before capture")
		}
	}
	if e = record("transition_order", nil); e != nil {
		return e
	}
	return record("reinstalled_for_timeout", m.EnsureCompanyRoute(guard, tun, prefix))
}
