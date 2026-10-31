package app

import (
	"bytes"
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

func TestOfflineConfigurationCommands(t *testing.T) {
	profile := testutil.PrivateTempDir(t)
	var output bytes.Buffer
	cli := CLI{Out: &output, Err: &output}
	if err := cli.Run([]string{"init", "--profile", profile}); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := cli.Run([]string{"config", "validate", "--profile", profile}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"policy_only"`) || !strings.Contains(output.String(), `"nodes_checked": false`) {
		t.Fatal("missing partial-validation scope", output.String())
	}
	// Windows secure reads require an absolute path; CLI accepts relative input
	// with the same meaning as on macOS.
	if err := cli.Run([]string{"config", "validate", "--file", "../../examples/policy.json", "--profile", profile}); err != nil {
		t.Fatal("relative candidate path failed", err)
	}
	cfg, err := readPolicy(profile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.PersonalRules = []policy.Rule{{Type: "DOMAIN", Value: "override.example.org", Target: "reject"}}
	if err := securefile.Write(filepath.Join(profile, "policy.json"), cfg); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(profile, "source.yaml")
	if err := os.WriteFile(source, []byte(`proxies: [{type: vless, server: 203.0.113.7, port: 443, uuid: "fixture-node-secret", tls: true}]
rules: ["DOMAIN-SUFFIX,example.org,PROXY"]`), 0600); err != nil {
		t.Fatal(err)
	}
	sources := subscription.Sources{Nodes: subscription.Source{File: source, UseRules: true}}
	if err := securefile.Write(filepath.Join(profile, "sources.json"), sources); err != nil {
		t.Fatal(err)
	}
	if err := cli.Run([]string{"sync", "--profile", profile}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"override.example.org", "sub.example.org"} {
		output.Reset()
		if err := cli.Run([]string{"rules", "explain", target, "--profile", profile}); err != nil {
			t.Fatal(err)
		}
		var got policy.Explanation
		if err := json.Unmarshal(output.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if target == "override.example.org" && (got.Winner.Target != "reject" || len(got.Shadowed) != 2 || got.Shadowed[0].Source != "subscriptions.nodes") {
			t.Fatal(got)
		}
		if target == "sub.example.org" && (got.Winner.Source != "subscriptions.nodes" || got.Winner.Index != 1) {
			t.Fatal(got)
		}
		if strings.Contains(output.String(), "fixture-node-secret") || strings.Contains(output.String(), "source.yaml") {
			t.Fatal("private source or credentials disclosed")
		}
	}
	cfg.Company.Domains = append(cfg.Company.Domains, "added.corp.example.com")
	candidate := filepath.Join(profile, "candidate.json")
	if err := securefile.Write(candidate, cfg); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(profile, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := cli.Run([]string{"config", "validate", "--file", candidate, "--profile", profile}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"effective_policy"`) {
		t.Fatal(output.String())
	}
	after, err := os.ReadFile(filepath.Join(profile, "policy.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("validation changed active policy", err)
	}
	cfg.Company.CIDRs = []string{"203.0.113.7/32"}
	if err := securefile.Write(candidate, cfg); err != nil {
		t.Fatal(err)
	}
	if err := cli.Run([]string{"config", "validate", "--file", candidate, "--profile", profile}); err == nil {
		t.Fatal("candidate bypassed node endpoint checks")
	}
	for _, args := range [][]string{{"config"}, {"rules", "explain"}, {"config", "unknown"}, {"rules", "explain", "https://example.org/", "--profile", profile}} {
		if err := cli.Run(args); err == nil {
			t.Fatal("invalid command accepted", args)
		}
	}
}
