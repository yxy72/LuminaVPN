package application

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netlaunch/internal/app"
	"netlaunch/internal/engine"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/testutil"
)

func fixtureDesktop(t *testing.T) *Desktop {
	t.Helper()
	profile := testutil.PrivateTempDir(t)
	if err := securefile.Bytes(filepath.Join(profile, "policy.json"), []byte(app.Example)); err != nil {
		t.Fatal(err)
	}
	nodes := []policy.Node{{"type": "hysteria2", "name": "private-node-name-canary", "server": "private-server.example.com", "port": 443, "password": "private-password-canary"}}
	if err := securefile.Write(filepath.Join(profile, "nodes.json"), nodes); err != nil {
		t.Fatal(err)
	}
	d, err := NewDesktop(profile, filepath.Join(t.TempDir(), "missing-runtime"))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func savedRun(t *testing.T, d *Desktop, status engine.Status) string {
	t.Helper()
	run := filepath.Join(testutil.PrivateTempDir(t), "netlaunch-private-path-canary")
	if err := securefile.Dir(run); err != nil {
		t.Fatal(err)
	}
	if err := securefile.Write(filepath.Join(d.Profile, "current.json"), map[string]string{"run": run}); err != nil {
		t.Fatal(err)
	}
	if err := securefile.Write(filepath.Join(run, "status.json"), status); err != nil {
		t.Fatal(err)
	}
	return run
}

func TestReadOnlyProjectionOmitsCredentialsPathsAndRawStatus(t *testing.T) {
	d := fixtureDesktop(t)
	now := time.Now()
	savedRun(t, d, engine.Status{Phase: "ready", Lifecycle: "running", Updated: now, Personal: "P001", Error: "private-error-canary", Channels: map[string]engine.ChannelStatus{"personal": {State: "ready", Reason: "private-reason-canary", CheckedAt: now, PathState: "verified", ServiceState: "healthy"}}})
	nodes, err := d.ListNodes(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes.Items) != 1 || nodes.Items[0].Name != "P001" || nodes.Items[0].Selected || nodes.SelectionScope != "not_compared" {
		t.Fatal(nodes)
	}
	checks, err := d.Environment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{d.GetState(), d.InspectProfile(), nodes, checks, d.Recovery()} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{"private-node-name-canary", "private-server.example.com", "private-password-canary", "private-path-canary", "private-error-canary", "private-reason-canary", d.Profile} {
			if strings.Contains(string(raw), private) {
				t.Fatalf("private field disclosed: %s", private)
			}
		}
	}
	if len(d.GetState().Status.Channels) != 3 || d.GetState().RuntimeLiveness != "not_checked" {
		t.Fatal("missing independent channel evidence or false liveness")
	}
}

func TestNextStartInventoryDoesNotCompareGeneratedIDWithFrozenRun(t *testing.T) {
	d := fixtureDesktop(t)
	savedRun(t, d, engine.Status{Phase: "ready", Lifecycle: "running", Updated: time.Now(), Personal: "P001"})
	replacement := []policy.Node{{"type": "hysteria2", "name": "P001", "server": "replacement.example.com", "port": 443, "password": "replacement-password-canary"}}
	if err := securefile.Write(filepath.Join(d.Profile, "nodes.json"), replacement); err != nil {
		t.Fatal(err)
	}
	nodes, err := d.ListNodes(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes.Items) != 1 || nodes.Items[0].ID != "P001" || nodes.Items[0].Selected || nodes.SelectionScope != "not_compared" {
		t.Fatal("cache node misidentified as saved run selection", nodes)
	}
	if d.GetState().Status.Personal == nil || *d.GetState().Status.Personal != "P001" {
		t.Fatal("saved run label was lost")
	}
}

func TestDesktopAgesSavedEvidenceWithoutClaimingLiveProcess(t *testing.T) {
	d := fixtureDesktop(t)
	now := time.Now()
	d.Now = func() time.Time { return now }
	savedRun(t, d, engine.Status{Phase: "ready", Lifecycle: "running", Updated: now.Add(-100 * time.Second), Channels: map[string]engine.ChannelStatus{"company": {State: "ready", Reason: "path_verified", CheckedAt: now.Add(-100 * time.Second), PathState: "verified", ServiceState: "not_checked"}}})
	state := d.GetState()
	if state.Status.Channels["company"].State != "unknown" || state.Status.Channels["company"].PathState != "unknown" || !state.SnapshotStale || state.RuntimeLiveness != "not_checked" || state.Status.Phase != "degraded" {
		t.Fatal(state)
	}
}

func TestMissingPolicyDoesNotHideExistingRunOrRecovery(t *testing.T) {
	d := fixtureDesktop(t)
	run := savedRun(t, d, engine.Status{Phase: "stopping", Lifecycle: "stopping", Updated: time.Now()})
	if err := os.Remove(filepath.Join(d.Profile, "policy.json")); err != nil {
		t.Fatal(err)
	}
	if err := securefile.Bytes(filepath.Join(run, "STOP"), nil); err != nil {
		t.Fatal(err)
	}
	state := d.GetState()
	if state.ProfileConfigured || state.RunRef == nil || !state.RecoveryRequired || !state.StopRequested {
		t.Fatal(state)
	}
	if err := securefile.Bytes(filepath.Join(d.Profile, "current.json"), []byte(`{"run":"private-invalid-path-canary"}`)); err != nil {
		t.Fatal(err)
	}
	state = d.GetState()
	if !state.RecoveryRequired || state.Status.Phase != "interrupted" {
		t.Fatal(state)
	}
}

func TestRecoveryDescriptorPreservesNeedAndRespectsNativeCapability(t *testing.T) {
	d := fixtureDesktop(t)
	savedRun(t, d, engine.Status{Phase: "stopping", Lifecycle: "stopping", Updated: time.Now()})
	description := d.Recovery().(map[string]any)
	if description["required"] != true || description["run_ref"] == nil {
		t.Fatal("recovery need was hidden", description)
	}
	if app.DesktopBuild().Capabilities.NativeLifecycle {
		if description["available"] != true {
			t.Fatal("native recovery was hidden", description)
		}
	} else {
		if description["available"] != false || description["status"] != "unavailable" {
			t.Fatal("offline build advertised executable recovery", description)
		}
		instructions := description["instructions"].([]string)
		if len(instructions) == 0 || !strings.Contains(instructions[0], "创建该运行的原 CLI") {
			t.Fatal("offline recovery did not direct the user to the original CLI")
		}
	}
}

func TestFirstReadDoesNotInitializeMissingProfile(t *testing.T) {
	root := testutil.PrivateTempDir(t)
	profile := filepath.Join(root, "missing")
	d, err := NewDesktop(profile, root)
	if err != nil {
		t.Fatal(err)
	}
	if d.InspectProfile().Configured || d.GetState().ProfileConfigured {
		t.Fatal("missing profile claimed configured")
	}
	if _, err = d.ListNodes(0, 100); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Config(0, 100); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Subscriptions(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(profile); !os.IsNotExist(err) {
		t.Fatal("read created profile")
	}
}

func TestRulesPaginationIncludesWholeOrderedPlan(t *testing.T) {
	d := fixtureDesktop(t)
	cfg, err := app.DesktopPolicy(d.Profile)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 251; i++ {
		cfg.PersonalRules = append(cfg.PersonalRules, policy.Rule{Type: "DOMAIN", Value: fmt.Sprintf("rule-%03d.example.com", i), Target: "personal"})
	}
	if err := securefile.Write(filepath.Join(d.Profile, "policy.json"), cfg); err != nil {
		t.Fatal(err)
	}
	full, err := app.DesktopRules(d.Profile, cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := []policy.PlannedRule{}
	for offset := 0; offset < len(full); offset += 100 {
		value, err := d.Config(offset, 100)
		if err != nil {
			t.Fatal(err)
		}
		page := value.(map[string]any)
		rules := page["rules"].([]policy.PlannedRule)
		if len(rules) > 100 || page["total"] != len(full) || page["offset"] != offset {
			t.Fatal("pagination bounds or total incorrect")
		}
		got = append(got, rules...)
	}
	if len(got) != len(full) {
		t.Fatal("rule pagination dropped entries")
	}
	for i, rule := range full {
		if got[i] != rule {
			t.Fatal("rule order changed")
		}
	}
	for _, bounds := range [][2]int{{-1, 100}, {0, 101}, {50001, 100}, {0, 0}} {
		if _, err := d.Config(bounds[0], bounds[1]); err == nil {
			t.Fatal("invalid rule page accepted")
		}
	}
}

func TestCorruptTransactionRequiresReconciliation(t *testing.T) {
	d := fixtureDesktop(t)
	if err := securefile.Bytes(filepath.Join(d.Profile, "config-transaction.json"), []byte(`{"secret":"private-transaction-canary"}`)); err != nil {
		t.Fatal(err)
	}
	state := d.GetState()
	profile := d.InspectProfile()
	if !state.RecoveryRequired || !profile.TransactionPending {
		t.Fatal(state, profile)
	}
	if strings.Contains(strings.Join(profile.Issues, " "), "private-transaction-canary") {
		t.Fatal("raw transaction disclosed")
	}
}
