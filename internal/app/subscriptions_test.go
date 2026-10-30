package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/subscription"
	"netlaunch/internal/testutil"
)

func TestPrivateSubscriptionInitSyncAndFailedUpdate(t *testing.T) {
	root := testutil.PrivateTempDir(t)
	source := filepath.Join(root, "nodes.yaml")
	bootstrap := filepath.Join(root, "bootstrap.private.json")
	profile := filepath.Join(root, "profile")
	data := []byte(`proxies: [{type: vless, server: 203.0.113.7, port: 443, uuid: "fixture-node-secret", tls: true}]
rules: ["DOMAIN-SUFFIX,example.org,PROXY", "DOMAIN,local.example.org,DIRECT"]
dns: {nameserver: ["evil"]}
`)
	if e := os.WriteFile(source, data, 0600); e != nil {
		t.Fatal(e)
	}
	cfg, e := policy.Decode([]byte(Example))
	if e != nil {
		t.Fatal(e)
	}
	cfg.PersonalRules = []policy.Rule{{Type: "DOMAIN", Value: "local.example.org", Target: "reject"}}
	b := subscription.Bootstrap{Version: 1, Policy: cfg, Subscriptions: subscription.Sources{Nodes: subscription.Source{File: "nodes.yaml", UseRules: true}, IntervalMinutes: 1}}
	if e := securefile.Write(bootstrap, b); e != nil {
		t.Fatal(e)
	}
	var output bytes.Buffer
	cli := CLI{Out: &output, Err: &output}
	if e := cli.Run([]string{"init", "--file", bootstrap, "--profile", profile}); e != nil {
		t.Fatal(e)
	}
	sources, present, e := sourceConfig(profile)
	if e != nil || !present || sources.Nodes.File != source {
		t.Fatal(sources, present, e)
	}
	if _, e := os.Stat(filepath.Join(profile, "subscription-cache.json")); !os.IsNotExist(e) {
		t.Fatal("init fetched source")
	}
	if e := cli.Run([]string{"sync", "--profile", profile}); e != nil {
		t.Fatal(e)
	}
	cachePath := filepath.Join(profile, "subscription-cache.json")
	cache, e := cachedSubscription(profile, cfg, sources)
	if e != nil {
		t.Fatal(e)
	}
	effective, nodes, e := effectiveProfile(profile, cfg)
	if e != nil || len(nodes) != 1 || len(effective.PersonalRules) != 3 || effective.PersonalRules[0].Target != "reject" {
		t.Fatal("local precedence lost", e)
	}
	// An expired cache triggers a refresh; a malformed source must not replace it.
	cache.Updated = time.Now().Add(-2 * time.Hour)
	if e := securefile.Write(cachePath, cache); e != nil {
		t.Fatal(e)
	}
	before, e := securefile.Read(cachePath, 16<<20, true)
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(source, []byte("fixture-node-secret"), 0600)
	if e := cli.Run([]string{"sync", "--profile", profile}); e == nil {
		t.Fatal("invalid source replaced cache")
	}
	if e := cli.syncSubscriptions(options{profile: profile}, cfg, false); e != nil {
		t.Fatal("automatic update did not retain cache", e)
	}
	after, e := securefile.Read(cachePath, 16<<20, true)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("failed update changed cache", e)
	}
	if e := cli.Run([]string{"plan", "--profile", profile}); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(output.String(), "fixture-node-secret") {
		t.Fatal("credential disclosed")
	}
	cfg.Company.Domains = append(cfg.Company.Domains, "new.corp.example.com")
	if _, e := cachedSubscription(profile, cfg, sources); e == nil {
		t.Fatal("stale fingerprint accepted")
	}
	if e := cli.Run([]string{"import", "--file", source, "--profile", profile}); e == nil {
		t.Fatal("manual import bypassed subscription cache")
	}
}
func TestInitPreservesOrphanedSourceConfiguration(t *testing.T) {
	root := testutil.PrivateTempDir(t)
	profile := filepath.Join(root, "profile")
	path := filepath.Join(profile, "sources.json")
	if e := securefile.Bytes(path, []byte("existing")); e != nil {
		t.Fatal(e)
	}
	if e := (CLI{}).Run([]string{"init", "--profile", profile}); e == nil {
		t.Fatal("existing sources overwritten")
	}
	got, e := os.ReadFile(path)
	if e != nil || string(got) != "existing" {
		t.Fatal("existing source changed", e)
	}
	if _, e := os.Stat(filepath.Join(profile, "policy.json")); !os.IsNotExist(e) {
		t.Fatal("partial initialization")
	}
}
