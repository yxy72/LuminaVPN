//go:build windows

package main

import (
	"context"
	"errors"
	"netlaunch/internal/securefile"
	"netlaunch/internal/socketbind"
	"netlaunch/internal/winnet"
	"os"
	"path/filepath"
	"time"
)

// This is a second, fixture-only journal. The production journal must reject
// a route changed outside its transaction, while the independent probe still
// needs exact authority to undo the deliberately changed fixture after a crash.
type routeMutation struct {
	Original, Replacement winnet.Route
	Restored              bool
}

func validateMutation(v routeMutation, a winnet.Adapter) error {
	if v.Original.Validate() != nil || v.Replacement.Validate() != nil ||
		v.Original.Prefix != "192.0.2.2/32" || v.Original.NextHop != "0.0.0.0" ||
		v.Original.InterfaceIndex != a.Index || v.Original.InterfaceLUID != a.LUID ||
		a.Hardware || a.Type != 53 || a.GUID == "" || v.Original.Metric == 0 || v.Replacement.Metric != 0 {
		return errors.New("mutation is outside the owned route fixture")
	}
	normalized := v.Replacement
	normalized.Metric = v.Original.Metric
	if !winnet.OwnedEqual(normalized, v.Original) {
		return errors.New("mutation changed more than its recorded metric")
	}
	return nil
}

func restoreRouteMutation(files securefile.AdminStore, id string) error {
	var v routeMutation
	e := read(files, id, "probe-mutation.json", &v)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	var p plan
	if e = read(files, id, "probe-plan.json", &p); e != nil {
		return e
	}
	if p.Stage != "mutation" {
		return errors.New("mutation journal in an unrelated stage")
	}
	var a winnet.Adapter
	if e = read(files, id, "probe-adapter.json", &a); e != nil {
		return e
	}
	if a.Name != "NL-Probe-"+id[len("netlaunch-"):] {
		return errors.New("mutation adapter name differs")
	}
	if e = validateMutation(v, a); e != nil {
		return e
	}
	if v.Restored {
		return nil
	}
	j, e := manager(files, id).Store.Load()
	if e != nil {
		return e
	}
	found := false
	for _, pair := range j.Pairs {
		if winnet.OwnedEqual(pair.VPN.Route, v.Original) {
			found = true
		}
	}
	if !found {
		return errors.New("original route was not journaled by this run")
	}
	actual, e := winnet.Lookup(v.Original)
	if e != nil {
		return e
	}
	if actual != nil && !winnet.OwnedEqual(*actual, v.Original) {
		if !winnet.OwnedEqual(*actual, v.Replacement) {
			return errors.New("route differs from both recorded fixture states")
		}
		if e = winnet.ValidateAdapter(a, ""); e != nil {
			return e
		}
		// Delete only the independently journaled replacement. The production
		// recovery that follows still owns any remaining original/capture route.
		if e = winnet.Delete(v.Replacement); e != nil {
			return e
		}
	}
	v.Restored = true
	return files.Write(filepath.Join(id, "probe-mutation.json"), v)
}

func exerciseMutation(files securefile.AdminStore, id string, vpn winnet.Adapter) error {
	if e := exercisePair(files, id, vpn); e != nil {
		return e
	}
	m := manager(files, id)
	j, e := m.Store.Load()
	if e != nil {
		return e
	}
	if len(j.Pairs) != 1 || len(j.Guards) != 1 {
		return errors.New("unexpected mutation baseline")
	}
	pair, guard := j.Pairs[0], j.Guards[0].Spec
	status := map[string]any{}
	if e = read(files, id, "probe-native.json", &status); e != nil {
		return e
	}
	status["stage"] = "mutation"
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
	v := routeMutation{Original: pair.VPN.Route, Replacement: pair.VPN.Route}
	v.Replacement.Metric = 0
	if e = validateMutation(v, vpn); e != nil {
		return e
	}
	if e = files.Write(filepath.Join(id, "probe-mutation.json"), v); e != nil {
		return e
	}
	if e = winnet.Delete(v.Original); e != nil {
		return e
	}
	if _, e = winnet.Add(v.Replacement); e != nil {
		return e
	}
	if e = record("native_route_metric_changed", nil); e != nil {
		return e
	}
	var p plan
	if e = read(files, id, "probe-plan.json", &p); e != nil {
		return e
	}
	if p.Fault == "route-replaced" {
		if e = files.Write(filepath.Join(id, "probe-fault-triggered.json"), map[string]any{"fault": p.Fault, "time": time.Now()}); e != nil {
			return e
		}
		os.Exit(42)
	}
	if m.CheckCompanyAddress(guard, "192.0.2.2") == nil {
		return record("metric_drift_denied", errors.New("changed route still authorized"))
	}
	if e = record("metric_drift_denied", nil); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, dialErr := socketbind.DialChecked(ctx, vpn.Index, "192.0.2.1", "192.0.2.2:18443", func() error {
		return m.CheckCompanyAddress(guard, "192.0.2.2")
	})
	if c != nil {
		c.Close()
	}
	if dialErr == nil {
		return record("changed_route_connection_denied", errors.New("changed route allowed a new connection"))
	}
	if e = record("changed_route_connection_denied", nil); e != nil {
		return e
	}
	if m.RemoveCompanyRoute(guard, "192.0.2.2/32") == nil {
		return record("changed_route_deletion_refused", errors.New("production recovery accepted modified route"))
	}
	if e = record("changed_route_deletion_refused", nil); e != nil {
		return e
	}
	for _, expected := range []winnet.Route{v.Replacement, pair.Capture.Route} {
		actual, e := winnet.Lookup(expected)
		if e != nil {
			return e
		}
		if actual == nil || !winnet.OwnedEqual(*actual, expected) {
			return record("failed_delete_preserves_routes", errors.New("failed deletion removed or changed a route"))
		}
	}
	if e = record("failed_delete_preserves_routes", nil); e != nil {
		return e
	}
	if e = record("failed_delete_preserves_guard", m.CheckCompanyGuard(guard)); e != nil {
		return e
	}
	if e = record("fixture_mutation_recovered", restoreRouteMutation(files, id)); e != nil {
		return e
	}
	if e = record("pair_withdrawal_retried", m.RemoveCompanyRoute(guard, "192.0.2.2/32")); e != nil {
		return e
	}
	if e = record("pair_reestablished", m.EnsureCompanyRoute(guard, pair.TUN, "192.0.2.2/32")); e != nil {
		return e
	}
	if e = record("authorization_reestablished", m.CheckCompanyAddress(guard, "192.0.2.2")); e != nil {
		return e
	}
	repairedCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	c, e = socketbind.DialChecked(repairedCtx, vpn.Index, "192.0.2.1", "192.0.2.2:18443", func() error {
		return m.CheckCompanyAddress(guard, "192.0.2.2")
	})
	if c != nil {
		c.Close()
	}
	return record("reestablished_tcp", e)
}
