package app

import (
	"path/filepath"
	"testing"
	"time"

	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/testutil"
)

func TestDesktopLatencyMatchesCurrentInventory(t *testing.T) {
	profile := testutil.PrivateTempDir(t)
	cfg := policy.Config{Probes: []policy.Probe{{Channel: "personal", URL: "https://example.org/"}}}
	nodes := []policy.Node{{"name": "P001", "server": "node.example.org"}}
	now := time.Now()
	report := nodeLatencyReport{Inventory: nodeLatencyInventory(cfg, nodes), CheckedAt: now, Values: map[string]int{"P001": 0}}
	if err := securefile.Write(filepath.Join(profile, nodeLatencyFile), report); err != nil {
		t.Fatal(err)
	}
	values, checked := DesktopNodeLatency(profile, cfg, nodes, now)
	if ms, exists := values["P001"]; !exists || ms != 0 || !checked.Equal(now) {
		t.Fatal("fresh zero-millisecond sample was lost")
	}
	if values, _ := DesktopNodeLatency(profile, cfg, nodes, now.Add(nodeLatencyAge+time.Second)); values != nil {
		t.Fatal("expired sample was returned")
	}
	nodes[0]["server"] = "replacement.example.org"
	if values, _ := DesktopNodeLatency(profile, cfg, nodes, now); values != nil {
		t.Fatal("a reused node label inherited a different node's sample")
	}
}
