package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"path/filepath"
	"time"

	"netlaunch/internal/engine"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	p "netlaunch/internal/serviceprotocol"
)

const nodeLatencyFile = "node-latency.json"
const nodeLatencyAge = 5 * time.Minute

type nodeLatencyReport struct {
	Inventory [32]byte       `json:"inventory"`
	CheckedAt time.Time      `json:"checked_at"`
	Values    map[string]int `json:"values"`
}

func nodeLatencyInventory(cfg policy.Config, nodes []policy.Node) [32]byte {
	raw, _ := json.Marshal(struct {
		Probes []policy.Probe
		Nodes  []policy.Node
	}{cfg.Probes, nodes})
	defer clear(raw)
	return sha256.Sum256(raw)
}

// DesktopNodeLatency returns fresh samples only for the exact ordered
// inventory that was measured. Pxxx identifiers are reused after imports.
func DesktopNodeLatency(profile string, cfg policy.Config, nodes []policy.Node, now time.Time) (map[string]int, time.Time) {
	var report nodeLatencyReport
	raw, err := securefile.Read(filepath.Join(profile, nodeLatencyFile), 64<<10, true)
	if err != nil || json.Unmarshal(raw, &report) != nil {
		return nil, time.Time{}
	}
	age := now.Sub(report.CheckedAt)
	if age < 0 || age > nodeLatencyAge || report.Inventory != nodeLatencyInventory(cfg, nodes) {
		return nil, time.Time{}
	}
	return report.Values, report.CheckedAt
}

func (d DesktopCommands) MeasureNodes(ctx context.Context) (any, error) {
	if err := d.check(ctx); err != nil {
		return nil, err
	}
	unlock, err := securefile.Lock(filepath.Join(d.Profile, "node-latency.lock"), time.Second)
	if err != nil {
		return nil, &p.Error{Code: "NODE_PROBE_UNAVAILABLE", Retryable: true}
	}
	defer unlock()
	cfg, err := readPolicyForStorage(d.Profile)
	if err != nil {
		return nil, &p.Error{Code: "NODE_PROBE_UNAVAILABLE"}
	}
	nodes, err := DesktopWorkspaceNodes(d.Profile, cfg)
	if err != nil {
		return nil, &p.Error{Code: "NODE_PROBE_UNAVAILABLE"}
	}
	if len(nodes) == 0 {
		return nil, &p.Error{Code: "NODE_PROBE_NO_NODES"}
	}
	target := ""
	for _, probe := range cfg.Probes {
		if probe.Channel == "personal" {
			if target == "" {
				target = probe.URL
			}
			if probe.EffectivePurpose() == "path" {
				target = probe.URL
				break
			}
		}
	}
	if target == "" {
		return nil, &p.Error{Code: "NODE_PROBE_TARGET_MISSING"}
	}
	values, err := engine.MeasureDesktopLatency(ctx, d.Runtime, d.Profile, nodes, target)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &p.Error{Code: "NODE_PROBE_UNAVAILABLE", Retryable: true}
	}
	if len(values) == 0 {
		return nil, &p.Error{Code: "NODE_PROBE_UNAVAILABLE", Retryable: true}
	}
	report := nodeLatencyReport{Inventory: nodeLatencyInventory(cfg, nodes), CheckedAt: time.Now(), Values: values}
	if err = securefile.Write(filepath.Join(d.Profile, nodeLatencyFile), report); err != nil {
		return nil, &p.Error{Code: "NODE_PROBE_UNAVAILABLE", Retryable: true}
	}
	return map[string]any{"measured": len(values), "network_changes": false}, nil
}
