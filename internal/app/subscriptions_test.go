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
	if _, e := cachedSubscription(profile, cfg, sources); e != nil {
		t.Fatal("offline policy edit unnecessarily invalidated source cache", e)
	}
	if e := securefile.Write(filepath.Join(profile, "policy.json"), cfg); e != nil {
		t.Fatal(e)
	}
	if e := cli.Run([]string{"plan", "--profile", profile}); e != nil {
		t.Fatal("offline policy plan failed", e)
	}
	if e := cli.syncSubscriptions(options{profile: profile}, cfg, false); e != nil {
		t.Fatal("offline policy could not reuse expired validated content", e)
	}
	conflict := cfg
	conflict.Company.CIDRs = []string{"203.0.113.7/32"}
	if _, e := cachedSubscription(profile, conflict, sources); e == nil {
		t.Fatal("policy edit bypassed cached node endpoint authorization")
	}
	changedSource := sources
	changedSource.Nodes.File = filepath.Join(root, "different.yaml")
	if _, e := cachedSubscription(profile, cfg, changedSource); e == nil {
		t.Fatal("new source reused unrelated contents")
	}
	if e := cli.Run([]string{"import", "--file", source, "--profile", profile}); e == nil {
		t.Fatal("manual import bypassed subscription cache")
	}
}

func TestSubscriptionCacheReparsesLocallyAndSupportsLegacy(t *testing.T) {
	profile := testutil.PrivateTempDir(t)
	cfg, err := policy.Decode([]byte(Example))
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(profile, "source.yaml")
	if err := os.WriteFile(source, []byte(`proxies: [{type: vless, server: 203.0.113.7, port: 443, uuid: "fixture-secret", tls: true}]
rules: ["DOMAIN,local.example.org,Custom"]`), 0600); err != nil {
		t.Fatal(err)
	}
	sources := subscription.Sources{Nodes: subscription.Source{File: source, UseRules: true, Groups: map[string]string{"Custom": "personal"}}, IntervalMinutes: 60}
	if err := securefile.Write(filepath.Join(profile, "policy.json"), cfg); err != nil {
		t.Fatal(err)
	}
	if err := securefile.Write(filepath.Join(profile, "sources.json"), sources); err != nil {
		t.Fatal(err)
	}
	cli := CLI{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
	if err := cli.syncSubscriptions(options{profile: profile}, cfg, true); err != nil {
		t.Fatal(err)
	}
	sources, _, err = sourceConfig(profile)
	if err != nil {
		t.Fatal(err)
	}
	original, err := cachedSubscription(profile, cfg, sources)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	sources.Nodes.Groups = map[string]string{"Custom": "reject"}
	sources.IntervalMinutes = 120
	reparsed, err := cachedSubscription(profile, cfg, sources)
	if err != nil || len(reparsed.Result.Rules) != 1 || reparsed.Result.Rules[0].Target != "reject" {
		t.Fatal("mapping did not reparse cached source", err)
	}
	if !reparsed.Updated.Equal(original.Updated) {
		t.Fatal("local parse changed download freshness")
	}
	// A parser-version mismatch must also reparse rather than trust stored results.
	original.Fingerprint = "old-parser"
	original.Result.Rules[0].Target = "direct"
	path := filepath.Join(profile, "subscription-cache.json")
	if err := securefile.Write(path, original); err != nil {
		t.Fatal(err)
	}
	reparsed, err = cachedSubscription(profile, cfg, sources)
	if err != nil || reparsed.Result.Rules[0].Target != "reject" {
		t.Fatal("parser update did not reparse", err)
	}
	// Legacy data remains readable only with the exact old policy + sources.
	legacy := subscriptionCache{Version: 1, Fingerprint: fingerprint(cfg, sources), Updated: original.Updated, Result: reparsed.Result}
	if err := securefile.Write(path, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := cachedSubscription(profile, cfg, sources); err != nil {
		t.Fatal(err)
	}
	cfg.Company.Domains = append(cfg.Company.Domains, "new.corp.example.com")
	if _, err := cachedSubscription(profile, cfg, sources); err == nil {
		t.Fatal("legacy cache silently assumed source identity")
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
