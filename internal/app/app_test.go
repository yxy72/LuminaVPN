package app

import (
	"bytes"
	"netlaunch/internal/testutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitImportPlanWithoutNetworkChanges(t *testing.T) {
	var out, errs bytes.Buffer
	cli := CLI{&out, &errs}
	profile := filepath.Join(testutil.PrivateTempDir(t), "profile")
	if e := cli.Run([]string{"init", "--profile", profile}); e != nil {
		t.Fatal(e)
	}
	if e := cli.Run([]string{"init", "--profile", profile}); e == nil {
		t.Fatal("init overwrote profile")
	}
	input := filepath.Join(t.TempDir(), "nodes.yaml")
	os.WriteFile(input, []byte("proxies:\n- {type: hysteria2, server: '203.0.113.7', port: 443, password: 'test-private-password'}\n"), 0600)
	if e := cli.Run([]string{"import", "--profile", profile, "--file", input}); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	if e := cli.Run([]string{"plan", "--profile", profile}); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), "test-private-password") || !strings.Contains(out.String(), `"network_changes": false`) {
		t.Fatal("unsafe plan output")
	}
	if _, e := os.Stat(filepath.Join(profile, "current.json")); !os.IsNotExist(e) {
		t.Fatal("plan created an active run")
	}
}
func TestBadCommandsAndAuthMarker(t *testing.T) {
	cli := CLI{}
	if e := cli.Run([]string{"init", "extra"}); e == nil {
		t.Fatal("accepted extra input")
	}
	if e := cli.Run([]string{"_auth", "--run", "/private/tmp/unrelated"}); e == nil {
		t.Fatal("accepted unrelated authentication output directory")
	}
	if e := cli.Run([]string{"--help"}); e != nil {
		t.Fatal(e)
	}
}

func TestRuntimeCheckWorksWithoutProfile(t *testing.T) {
	var out bytes.Buffer
	profile := filepath.Join(testutil.PrivateTempDir(t), "absent")
	e := (CLI{Out: &out}).Run([]string{"check-runtime", "--profile", profile, "--runtime", filepath.Join(profile, "runtime")})
	if e == nil || !strings.Contains(out.String(), `"bundle_verified": false`) || strings.Contains(e.Error(), "policy") {
		t.Fatal(out.String(), e)
	}
	if _, e := os.Stat(profile); !os.IsNotExist(e) {
		t.Fatal("diagnostic wrote a profile")
	}
}

func TestMixedImportIsExplicitAndDoesNotExposeSecrets(t *testing.T) {
	var out bytes.Buffer
	cli := CLI{Out: &out}
	profile := filepath.Join(testutil.PrivateTempDir(t), "profile")
	if e := cli.Run([]string{"init", "--profile", profile}); e != nil {
		t.Fatal(e)
	}
	input := filepath.Join(t.TempDir(), "mixed.yaml")
	data := []byte("proxies:\n- {type: vless, server: node.example.com, port: 443, uuid: hidden-value, tls: true}\n- {type: ss, server: 203.0.113.1, port: 443, password: hidden-value}\n")
	if e := os.WriteFile(input, data, 0600); e != nil {
		t.Fatal(e)
	}
	if e := cli.Run([]string{"import", "--profile", profile, "--file", input}); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "Skipped subscription entry 2") || !strings.Contains(out.String(), "Imported 1 nodes") || strings.Contains(out.String(), "hidden-value") {
		t.Fatal("incomplete or private import output")
	}
	report, e := os.ReadFile(filepath.Join(profile, "import-result.json"))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(report), "hidden-value") {
		t.Fatal("secret persisted in public import metadata")
	}
}
