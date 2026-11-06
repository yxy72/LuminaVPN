package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netlaunch/internal/app"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/subscription"
)

func storedWorkspace(t *testing.T) *Desktop {
	t.Helper()
	d, _ := mockClient(t)
	if err := securefile.Dir(d.Profile); err != nil {
		t.Fatal(err)
	}
	cfg := policy.Config{Version: 1, Ports: policy.Ports{Proxy: 7890, DNS: 1053}}
	if err := securefile.Write(filepath.Join(d.Profile, "policy.json"), cfg); err != nil {
		t.Fatal(err)
	}
	return d
}
func TestClientStoredAllOffInventoryDoesNotRequireRuntimeFields(t *testing.T) {
	d := storedWorkspace(t)
	if _, err := app.DesktopPolicy(d.Profile); err == nil {
		t.Fatal("default CLI/Mac reader was loosened")
	}
	if !d.InspectProfile().PolicyValid {
		t.Fatal("client storage policy rejected")
	}
	nodes, err := d.ListNodes(0, 100)
	if err != nil || nodes.Total != 0 || len(nodes.Items) != 0 {
		t.Fatal("missing inventory is not empty", err)
	}
	if _, err := d.Config(0, 100); err != nil {
		t.Fatal("stored static plan unavailable", err)
	}
	if _, err := d.Subscriptions(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClientRequest(context.Background(), "workspace.read", scopedWorkspaceJSON(d, `{"action":"document"}`)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nodes.json", "sources.json", "subscription-cache.json", "current.json"} {
		if _, err := os.Lstat(filepath.Join(d.Profile, name)); !os.IsNotExist(err) {
			t.Fatal("read created a workspace file")
		}
	}
}

func TestClientSnapshotInventoryIsLocalReadOnlyAndRedacted(t *testing.T) {
	d := storedWorkspace(t)
	sources := subscription.Sources{Nodes: subscription.Source{URL: "https://subscription.example.test/private-canary"}}
	if err := securefile.Write(filepath.Join(d.Profile, "sources.json"), sources); err != nil {
		t.Fatal(err)
	}
	sourceIdentity, _ := json.Marshal(struct{ URL, File string }{sources.Nodes.URL, ""})
	sum := sha256.Sum256(sourceIdentity)
	data := []byte(`{"proxies":[{"type":"hysteria2","name":"private-name-canary","server":"node.example.test","port":443,"password":"private-secret-canary"}]}`)
	contentHash := sha256.Sum256(data)
	snapshot := subscription.Snapshot{Contents: []subscription.Content{{SourceID: hex.EncodeToString(sum[:]), SHA256: hex.EncodeToString(contentHash[:]), Data: data}}}
	cachePath := filepath.Join(d.Profile, "subscription-cache.json")
	if err := securefile.Write(cachePath, map[string]any{"version": 2, "fingerprint": "old-parser-fingerprint", "updated": time.Now().UTC(), "result": subscription.Result{}, "snapshot": snapshot}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := d.ListNodes(0, 100)
	if err != nil || nodes.Total != 1 || nodes.Items[0].ID != "P001" {
		t.Fatal("local snapshot not reinterpreted", err)
	}
	summary, err := d.Subscriptions()
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal([]any{nodes, summary})
	for _, secret := range []string{"private-canary", "private-name-canary", "private-secret-canary", "node.example.test", "subscription.example.test"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("private source content escaped inventory DTO")
		}
	}
	if summary.(map[string]any)["cache_available"] != true {
		t.Fatal("validated local snapshot not available")
	}
	after, err := os.ReadFile(cachePath)
	if err != nil || string(before) != string(after) {
		t.Fatal("read rewrote the private cache")
	}
}
