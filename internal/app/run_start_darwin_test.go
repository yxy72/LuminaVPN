package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netlaunch/internal/engine"
)

func TestMacCanceledStartPinsStopAfterNativeAuthorization(t *testing.T) {
	profile, first, second := macStopFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stop, err := bindRunStop(ctx, options{run: first})
	if err != nil {
		t.Fatal(err)
	}
	defer stop.Close()
	launch := func(ctx context.Context, action, run string) error {
		if action != "serve" || run != first {
			t.Fatalf("unexpected launch: %s %s", action, run)
		}
		setStopFixtureCurrent(t, profile, second)
		cancel()
		// Native authorization may return success as the app cancels.
		return nil
	}
	_, err = launchPreparedRun(ctx, stop, launch, func(string) (engine.Status, error) {
		t.Fatal("late native success should not begin polling readiness")
		return engine.Status{}, nil
	}, time.Second, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(first, "STOP")); err != nil {
		t.Fatalf("cancel did not publish STOP: %v", err)
	}
	requireNoStopMarker(t, second)
}

func TestMacUnsettledStartTimeoutRequestsIndependentStop(t *testing.T) {
	_, first, _ := macStopFixture(t)
	stop, err := bindRunStop(t.Context(), options{run: first})
	if err != nil {
		t.Fatal(err)
	}
	defer stop.Close()
	_, err = launchPreparedRun(t.Context(), stop, func(context.Context, string, string) error { return nil },
		func(string) (engine.Status, error) { return engine.Status{Phase: "starting"}, nil }, 20*time.Millisecond, time.Millisecond)
	if err == nil {
		t.Fatal("an unresolved launch was reported ready")
	}
	if _, err := os.Stat(filepath.Join(first, "STOP")); err != nil {
		t.Fatalf("timed out launch did not publish STOP: %v", err)
	}
}

func TestMacSuccessfulStartLeavesRunActive(t *testing.T) {
	_, first, _ := macStopFixture(t)
	stop, err := bindRunStop(t.Context(), options{run: first})
	if err != nil {
		t.Fatal(err)
	}
	defer stop.Close()
	status, err := launchPreparedRun(t.Context(), stop, func(context.Context, string, string) error { return nil },
		func(string) (engine.Status, error) { return engine.Status{Phase: "ready"}, nil }, time.Second, time.Millisecond)
	if err != nil || status.Phase != "ready" {
		t.Fatal(status.Phase, err)
	}
	requireNoStopMarker(t, first)
}

func TestLateAuthReceiptCannotRecreateOrWriteIntoReplacedRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-request")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	identity, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+"-retired"); err != nil {
		t.Fatal(err)
	}
	if err := writeAuthReceipt(path, identity, "done"); err == nil {
		t.Fatal("late helper recreated a retired authentication request")
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeAuthReceipt(path, identity, "done"); err == nil {
		t.Fatal("late helper wrote an authentication receipt into a different request")
	}
}
