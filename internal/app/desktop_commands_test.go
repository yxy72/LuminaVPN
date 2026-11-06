package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/subscription"
	"netlaunch/internal/testutil"
)

func desktopDisabledFixture(t *testing.T) (DesktopCommands, policy.Config, []byte) {
	t.Helper()
	var cfg policy.Config
	if err := json.Unmarshal([]byte(Example), &cfg); err != nil {
		t.Fatal(err)
	}
	// First-use storage is valid without fake company credentials, whitelist,
	// probes, a node pool, or enabled channels. Runtime validation is separate.
	cfg.Company, cfg.Personal = policy.Channel{}, policy.Channel{}
	cfg.VPN, cfg.Probes = policy.VPN{}, nil
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d := DesktopCommands{Profile: filepath.Join(testutil.PrivateTempDir(t), "profile")}
	return d, cfg, raw
}

func TestDesktopDisabledFirstUseAndRevisionSafeApplyRollback(t *testing.T) {
	d, cfg, raw := desktopDisabledFixture(t)
	ctx := context.Background()
	if _, err := d.Initialize(ctx, raw, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(d.Profile, "nodes.json")); !os.IsNotExist(err) {
		t.Fatal("initialization created a node pool")
	}
	if _, err := os.Stat(filepath.Join(d.Profile, "session.json")); !os.IsNotExist(err) {
		t.Fatal("initialization created an auth session")
	}
	old := policyRevision(cfg)
	before, err := os.ReadFile(filepath.Join(d.Profile, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Ports.Proxy++
	changed, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ApplyDraft(ctx, changed, strings.Repeat("0", 64)); err == nil {
		t.Fatal("stale edit accepted")
	}
	after, err := os.ReadFile(filepath.Join(d.Profile, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("stale edit changed policy")
	}
	if _, err = d.ApplyDraft(ctx, changed, old); err != nil {
		t.Fatal(err)
	}
	if _, err = d.History(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Rollback(ctx, old, policyRevision(cfg)); err != nil {
		t.Fatal(err)
	}
	current, err := readPolicyForStorage(d.Profile)
	if err != nil {
		t.Fatal(err)
	}
	if policyRevision(current) != old {
		t.Fatal("rollback did not restore the exact revision")
	}
}

func TestDesktopInitializeRejectsOverwriteAndSourcePaths(t *testing.T) {
	d, _, raw := desktopDisabledFixture(t)
	ctx := context.Background()
	if _, err := d.Initialize(ctx, raw, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Initialize(ctx, raw, nil); err == nil {
		t.Fatal("existing profile overwritten")
	}
	if _, err := d.Initialize(ctx, raw, []byte("{}")); err == nil {
		t.Fatal("ambiguous initialization accepted")
	}
	before, err := securefile.Read(filepath.Join(d.Profile, "policy.json"), 1<<20, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SaveSources(ctx, []byte(`{"nodes":{"file":"C:\\Windows\\win.ini"}}`), policyRevisionMust(t, before)); err == nil {
		t.Fatal("RPC source accepted arbitrary local file")
	}
}

func policyRevisionMust(t *testing.T, raw []byte) string {
	t.Helper()
	cfg, err := policy.DecodeForStorage(raw)
	if err != nil {
		t.Fatal(err)
	}
	return policyRevision(cfg)
}

func TestDesktopCancellationAndOpaqueRunBoundary(t *testing.T) {
	d, _, raw := desktopDisabledFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Initialize(ctx, raw, nil); err == nil {
		t.Fatal("canceled operation wrote configuration")
	}
	if _, err := os.Stat(d.Profile); !os.IsNotExist(err) {
		t.Fatal("canceled operation created profile")
	}
	for _, id := range []string{"../outside", "netlaunch-../outside", strings.Repeat("a", 32), "netlaunch-" + strings.Repeat("g", 32)} {
		if _, err := desktopRunPath(d.Profile, id); err == nil {
			t.Fatal("unsafe run ID accepted")
		}
	}
}

func TestDesktopStorageImportsAndExplainsBeforeRuntimeSetup(t *testing.T) {
	d, cfg, raw := desktopDisabledFixture(t)
	ctx := context.Background()
	if _, err := d.Initialize(ctx, raw, nil); err != nil {
		t.Fatal(err)
	}
	if err := cfg.ValidateForIntent(desktopStorageIntent()); err == nil {
		t.Fatal("fixture unexpectedly satisfies runtime prerequisites")
	}
	if _, err := d.Explain(ctx, "unlisted.example"); err != nil {
		t.Fatal("saved rule explanation required runtime prerequisites:", err)
	}
	if _, err := d.ImportNodes(ctx, []byte("proxies:\n- {type: hysteria2, server: '203.0.113.7', port: 443, password: 'fixture-value'}\n")); err != nil {
		t.Fatal("node import required runtime prerequisites:", err)
	}
	nodes, err := readNodes(d.Profile)
	if err != nil || len(nodes) != 1 {
		t.Fatal("node import was not persisted", err)
	}
	if _, _, err = effectiveResultForStorage(cfg, subscription.Result{Nodes: nodes}); err != nil {
		t.Fatal("valid subscription content required runtime prerequisites:", err)
	}
	if _, _, err = effectiveResultForStorage(cfg, subscription.Result{Nodes: []policy.Node{{"type": "unsupported"}}}); err == nil {
		t.Fatal("storage accepted malformed subscription content")
	}
}

func TestDesktopSubscriptionStorageRefreshRetainsCacheOnFailure(t *testing.T) {
	d, cfg, raw := desktopDisabledFixture(t)
	ctx := context.Background()
	if _, err := d.Initialize(ctx, raw, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SaveSources(ctx, []byte(`{"nodes":{"url":"https://subscription.example/nodes"}}`), policyRevision(cfg)); err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(d.Profile, "subscription-cache.json")
	if err := securefile.Write(cachePath, map[string]any{"fixture": "previous"}); err != nil {
		t.Fatal(err)
	}
	before, err := securefile.Read(cachePath, 1<<20, true)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	fetch := func(context.Context, subscription.Sources) (subscription.Snapshot, subscription.Result, error) {
		called = true
		return subscription.Snapshot{}, subscription.Result{}, context.Canceled
	}
	if err := syncSubscriptionsWith(ctx, d.Profile, cfg, desktopStorageIntent(), true, true, fetch); err == nil || !called {
		t.Fatal("storage refresh did not reach the bounded fetch independently of runtime setup", err)
	}
	after, err := securefile.Read(cachePath, 1<<20, true)
	if err != nil || string(before) != string(after) {
		t.Fatal("failed refresh replaced the prior cache", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	called = false
	if err := syncSubscriptionsWith(canceled, d.Profile, cfg, desktopStorageIntent(), true, true, fetch); err == nil || called {
		t.Fatal("canceled refresh performed fetch work")
	}
}
