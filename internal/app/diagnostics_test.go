package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netlaunch/internal/buildinfo"
	"netlaunch/internal/engine"
	"netlaunch/internal/securefile"
	"netlaunch/internal/testutil"
)

func TestBuildModesDescribeActualGates(t *testing.T) {
	for _, tc := range []struct {
		os               string
		home, validation bool
		mode             string
		native           bool
		limit            int
	}{
		{"windows", false, false, "windows_offline", false, 0},
		{"windows", true, false, "windows_home", true, 43200},
		{"windows", false, true, "windows_validation", true, 2700},
		{"windows", true, true, "invalid_windows_tags", false, 0},
		{"darwin", false, false, "macos_experimental", true, 0},
		{"linux", false, false, "offline", false, 0},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			got := describeBuild(buildinfo.Info{}, tc.os, tc.home, tc.validation)
			if got.Mode != tc.mode || got.Capabilities.NativeLifecycle != tc.native || got.Capabilities.MaximumSessionSeconds != tc.limit {
				t.Fatalf("incorrect build capabilities: %+v", got)
			}
		})
	}
	var out bytes.Buffer
	c := CLI{Out: &out}
	if err := c.Run([]string{"version"}); err != nil || out.String() != Version+"\n" {
		t.Fatal(out.String(), err)
	}
	out.Reset()
	if err := c.Run([]string{"version", "--json"}); err != nil {
		t.Fatal(err)
	}
	var got buildIdentity
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || got.Version != Version || got.Mode == "" {
		t.Fatal(out.String(), err)
	}
	if err := c.Run([]string{"version", "unexpected"}); err == nil {
		t.Fatal("ignored extra arguments")
	}
}

func TestDiagnosticsAllowlistRejectsPrivateAndUnknownFields(t *testing.T) {
	secret := "private-company-domain.example.invalid"
	now := time.Now()
	s := engine.Status{
		Phase: "ready", Lifecycle: "running", Updated: now.Add(-time.Hour),
		Personal: secret, Error: "probe " + secret, RecoveryReason: secret,
		Channels: map[string]engine.ChannelStatus{
			"company":  {State: "ready", Reason: "path_verified", CheckedAt: now.Add(-time.Minute * 2), NextAction: secret, PathState: "verified", ServiceState: "not_checked", ProbeScope: "system_tun"},
			"personal": {State: secret, Reason: secret, NextAction: secret, PathState: secret, ServiceState: secret, ProbeScope: secret},
			secret:     {State: secret},
		},
	}
	d := diagnosticProjection(s, now)
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), secret) || len(d.Channels) != 3 {
		t.Fatal("private status escaped", string(b))
	}
	if d.Phase != "degraded" || d.Channels["company"].State != "unknown" || d.Channels["personal"].State != "unknown" || !d.HasError || *d.SnapshotAgeSeconds != 3600 {
		t.Fatal("lost stale evidence or safe failure signal", string(b))
	}
	s.Phase, s.Lifecycle = secret, secret
	s.Updated = now.Add(time.Hour)
	d = diagnosticProjection(s, now)
	if d.Phase != "unknown" || d.Lifecycle != "unknown" || d.SnapshotAgeSeconds != nil {
		t.Fatal(d)
	}
}

func TestDiagnosticsExportReadsOnlySavedStatus(t *testing.T) {
	root := testutil.PrivateTempDir(t)
	profile := filepath.Join(root, "not-created")
	var out bytes.Buffer
	cli := CLI{Out: &out}
	if err := cli.Run([]string{"diagnostics", "export", "--profile", profile}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"no_current_run"`) {
		t.Fatal(out.String())
	}
	if _, err := os.Lstat(profile); !os.IsNotExist(err) {
		t.Fatal("diagnostics mutated profile", err)
	}
	run := filepath.Join(root, "netlaunch-fixture")
	if err := securefile.Dir(run); err != nil {
		t.Fatal(err)
	}
	statusPath := filepath.Join(run, "status.json")
	s := engine.Status{Phase: "stopped", Lifecycle: "stopped", Personal: "PRIVATE_NODE", Error: "PRIVATE_LOG"}
	if err := securefile.Write(statusPath, s); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.Bytes(filepath.Join(run, "auth.json"), []byte("PRIVATE_TOKEN")); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := cli.Run([]string{"diagnostics", "export", "--run", run}); err != nil {
		t.Fatal(err)
	}
	var report diagnosticReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.StatusRead != "available" || report.RuntimeLiveness != "not_checked" || report.Status.Phase != "stopped" {
		t.Fatal(out.String())
	}
	for _, private := range []string{"PRIVATE_", run, "auth.json", "status.json"} {
		if strings.Contains(out.String(), private) {
			t.Fatal("private data escaped", out.String())
		}
	}
	after, err := os.ReadFile(statusPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("status modified", err)
	}
	if err := securefile.Bytes(statusPath, []byte("PRIVATE_MALFORMED_JSON")); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := cli.Run([]string{"diagnostics", "export", "--run", run}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"status_unavailable"`) || strings.Contains(out.String(), "PRIVATE_") {
		t.Fatal(out.String())
	}
}
