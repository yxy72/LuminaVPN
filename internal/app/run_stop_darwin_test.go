//go:build darwin

package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netlaunch/internal/engine"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/testutil"
)

func macStopFixture(t *testing.T) (profile, first, second string) {
	t.Helper()
	profile, err := filepath.EvalSymlinks(testutil.PrivateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := engine.OwnerIdentity()
	if err != nil {
		t.Fatal(err)
	}
	config, err := policy.Decode([]byte(Example))
	if err != nil {
		t.Fatal(err)
	}
	makeRun := func(name string) string {
		run := filepath.Join(profile, "runs", name)
		if err := securefile.Write(filepath.Join(run, "manifest.json"), engine.Manifest{Version: 1, Owner: owner, Config: config}); err != nil {
			t.Fatal(err)
		}
		return run
	}
	first, second = makeRun("netlaunch-first"), makeRun("netlaunch-second")
	setStopFixtureCurrent(t, profile, first)
	return profile, first, second
}

func setStopFixtureCurrent(t *testing.T, profile, run string) {
	t.Helper()
	if err := securefile.Write(filepath.Join(profile, "current.json"), map[string]string{"run": run}); err != nil {
		t.Fatal(err)
	}
}

func writeStopFixtureReport(t *testing.T, run, phase string) {
	t.Helper()
	if err := securefile.Write(filepath.Join(run, "status.json"), engine.Status{Phase: phase, Updated: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func requireNoStopMarker(t *testing.T, run string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(run, "STOP")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected STOP marker: %v", err)
	}
}

func TestMacStopStaysBoundWhenCurrentRunChanges(t *testing.T) {
	profile, first, second := macStopFixture(t)
	stop, err := BindCurrentRunStop(t.Context(), profile)
	if err != nil {
		t.Fatal(err)
	}
	defer stop.Close()
	setStopFixtureCurrent(t, profile, second)
	writeStopFixtureReport(t, second, "stopped")
	if err := stop.Request(t.Context()); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(first, "STOP")
	both, err := os.Lstat(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := stop.Request(t.Context()); err != nil {
		t.Fatal(err)
	}
	again, err := os.Lstat(marker)
	if err != nil || !os.SameFile(both, again) {
		t.Fatal("repeated stop replaced the marker", err)
	}
	requireNoStopMarker(t, second)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if err := stop.waitForStoppedReport(ctx, time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("a different run's report satisfied the wait", err)
	}
	writeStopFixtureReport(t, first, "stopped")
	if err := stop.WaitForStoppedReport(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestMacStopRejectsReplacementAndCancellation(t *testing.T) {
	profile, first, _ := macStopFixture(t)
	stop, err := BindCurrentRunStop(t.Context(), profile)
	if err != nil {
		t.Fatal(err)
	}
	defer stop.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := stop.Request(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	requireNoStopMarker(t, first)
	if err := os.Rename(first, first+"-moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(first, 0700); err != nil {
		t.Fatal(err)
	}
	if err := stop.recover(t.Context(), func(string) error { t.Fatal("launched recovery for replacement run"); return nil }); err == nil {
		t.Fatal("recovered a replaced directory")
	}
	requireNoStopMarker(t, first)
	requireNoStopMarker(t, first+"-moved")
}

func TestMacExplicitRecoveryRequiresOriginalRunReport(t *testing.T) {
	profile, first, second := macStopFixture(t)
	stop, err := BindCurrentRunStop(t.Context(), profile)
	if err != nil {
		t.Fatal(err)
	}
	defer stop.Close()
	setStopFixtureCurrent(t, profile, second)
	writeStopFixtureReport(t, second, "stopped")
	verifyLaunch := func(run string) error {
		t.Helper()
		if run != first {
			t.Fatal("recovery targeted a different run")
		}
		if _, err := os.Stat(filepath.Join(run, "STOP")); err != nil {
			t.Fatal("native recovery submitted before ordinary STOP", err)
		}
		return nil
	}
	if err := stop.recover(t.Context(), verifyLaunch); err == nil {
		t.Fatal("launch return alone was accepted as a stopped report")
	}
	if err := stop.recover(t.Context(), func(run string) error {
		if err := verifyLaunch(run); err != nil {
			return err
		}
		writeStopFixtureReport(t, run, "stopped")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	requireNoStopMarker(t, second)
}

func TestMacDownKeepsExplicitHistoricalRunSemantics(t *testing.T) {
	profile, first, second := macStopFixture(t)
	setStopFixtureCurrent(t, profile, second)
	writeStopFixtureReport(t, first, "stopped")
	var out bytes.Buffer
	if err := (CLI{Out: &out}).down(options{profile: profile, run: first}); err != nil || out.String() != "Already stopped.\n" {
		t.Fatal(out.String(), err)
	}
	requireNoStopMarker(t, first)
	requireNoStopMarker(t, second)
}
