package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
)

func storedStateFixture(t *testing.T) State {
	t.Helper()
	raw, err := os.ReadFile("../../examples/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	s := State{Version: currentStateVersion, Phase: "ready", Heartbeat: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Manifest: Manifest{Version: 1, Config: cfg, Owner: 501, Executable: "fixture-executable", Binding: policy.Binding{Physical: "en4", VPN: "utun32", TUN: "utun33", ControllerPort: 19091}, Network: platform.Network{Interface: "en4", Address: "192.0.2.10"}}, Runner: platform.Identity{PID: 123, Birth: "fixture-birth", Executable: "fixture-executable", Command: "fixture-command"}}
	s.Routes = []OwnedRoute{{Route: platform.Route{Prefix: "192.0.2.1/32", Gateway: "192.0.2.254", Interface: "en4"}, State: "planned"}}
	s.DNS = map[string]DNSChange{"fixture-service": {Before: []string{"192.0.2.53"}, After: []string{"127.0.0.1"}}}
	s.Children = []Child{{Role: "vpn", PID: 456, Birth: "child-birth", Args: []string{"fixture-openconnect"}}}
	s.RunSpecDigest = runSpecDigest(immutableRunSpec(s.Manifest))
	return s
}

func TestCompactSnapshotPreservesNativeRecoveryAndDynamicBindings(t *testing.T) {
	s := storedStateFixture(t)
	spec, _ := json.Marshal(immutableRunSpec(s.Manifest))
	s.Manifest.Binding.VPN = "utun34"
	s.Manifest.Network.Interface = "en5"
	record, err := stateRecord(&s)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(s.Manifest.Config.Company.Domains[0])) || bytes.Contains(raw, []byte(`"config"`)) {
		t.Fatal("snapshot copied immutable policy")
	}
	restored, err := decodeState(raw, func() ([]byte, error) { return spec, nil })
	if err != nil || !reflect.DeepEqual(restored, s) {
		t.Fatal("lost planned resources or current network bindings", err)
	}
	s.Manifest.Config.VPN.Server = "https://changed.example.com"
	if _, err := stateRecord(&s); err == nil {
		t.Fatal("mutable policy was persisted in an active run")
	}
}

func TestRunSpecCannotBeMissingReplacedOrMixedWithLegacyState(t *testing.T) {
	s := storedStateFixture(t)
	record, _ := stateRecord(&s)
	raw, _ := json.Marshal(record)
	if _, err := decodeState(raw, func() ([]byte, error) { return nil, os.ErrNotExist }); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	altered := immutableRunSpec(s.Manifest)
	altered.Owner++
	spec, _ := json.Marshal(altered)
	if _, err := decodeState(raw, func() ([]byte, error) { return spec, nil }); err == nil {
		t.Fatal("substituted spec accepted")
	}
	full, _ := json.Marshal(s)
	if _, err := decodeState(full, func() ([]byte, error) { return spec, nil }); err == nil {
		t.Fatal("mixed full/compact record accepted")
	}
	var shape map[string]any
	_ = json.Unmarshal(raw, &shape)
	shape["manifest"].(map[string]any)["binding"] = nil
	bad, _ := json.Marshal(shape)
	if _, err := decodeState(bad, func() ([]byte, error) { return spec, nil }); err == nil {
		t.Fatal("missing current binding accepted")
	}
}

func TestLegacyRecoveryRecordIsNotMigrated(t *testing.T) {
	s := storedStateFixture(t)
	s.Version, s.RunSpecDigest = 1, ""
	record, err := stateRecord(&s)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(record)
	if !bytes.Contains(raw, []byte(s.Manifest.Config.Company.Domains[0])) {
		t.Fatal("legacy policy removed")
	}
	restored, err := decodeState(raw, func() ([]byte, error) { t.Fatal("legacy run requires a new spec"); return nil, nil })
	if err != nil || !reflect.DeepEqual(restored, s) {
		t.Fatal(err)
	}
}

func TestAliveHeartbeatCannotConcealStalledControlLoop(t *testing.T) {
	s := storedStateFixture(t)
	s.LastReady = s.Heartbeat
	m := baselineMonitor(s)
	for i := 1; i <= 40; i++ {
		var err error
		m, err = advanceMonitor(s, m, s.Heartbeat.Add(time.Duration(i)*time.Second), false)
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := monitorFailure(s, m, m.AliveAt); got != "coordinator_stalled" {
		t.Fatal(got)
	}
	m, err := advanceMonitor(s, m, m.AliveAt, true)
	if err != nil || monitorFailure(s, m, m.AliveAt) != "" {
		t.Fatal(err)
	}
	if monitorFailure(s, m, m.AliveAt.Add(36*time.Second)) != "coordinator_unresponsive" {
		t.Fatal("dead process heartbeat remained valid")
	}
	if _, err := advanceMonitor(s, m, m.AliveAt.Add(-time.Second), true); err == nil {
		t.Fatal("clock reversal accepted")
	}
	s.Version = 1
	m.ProgressAt = m.AliveAt.Add(-time.Hour)
	if monitorFailure(s, m, m.AliveAt) != "" {
		t.Fatal("legacy monitoring semantics changed")
	}
}

func TestMonitorIdentityAndStartupAllowance(t *testing.T) {
	s := storedStateFixture(t)
	s.Phase = "preparing"
	m := baselineMonitor(s)
	m.AliveAt = m.AliveAt.Add(60 * time.Second)
	if monitorFailure(s, m, m.AliveAt) != "" {
		t.Fatal("startup allowance lost")
	}
	m.AliveAt = m.AliveAt.Add(31 * time.Second)
	if monitorFailure(s, m, m.AliveAt) != "coordinator_stalled" {
		t.Fatal("startup can stall forever")
	}
	m.Runner.PID++
	raw, _ := json.Marshal(m)
	decoded, err := decodeMonitor(raw, s)
	if err != nil || !decoded.AliveAt.Equal(s.Heartbeat) {
		t.Fatal("old coordinator renewed new identity", err)
	}
	m.RunSpecDigest = "other-run"
	raw, _ = json.Marshal(m)
	if _, err := decodeMonitor(raw, s); err == nil {
		t.Fatal("foreign run monitor accepted")
	}
}
