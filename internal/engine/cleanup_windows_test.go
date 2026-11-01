//go:build windows

package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/testutil"
	"netlaunch/internal/winstate"
)

func TestCleanupChecksPrivilegedEvidenceAndReferences(t *testing.T) {
	if err := securefile.RequireAdmin(); err != nil {
		t.Skip("administrator fixture unavailable", err)
	}
	profile := testutil.PrivateTempDir(t)
	profile, err := filepath.EvalSymlinks(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.Dir(filepath.Join(profile, "runs")); err != nil {
		t.Fatal(err)
	}
	run, err := securefile.TempDir(filepath.Join(profile, "runs"), "netlaunch-")
	if err != nil {
		t.Fatal(err)
	}
	files, id, err := winFiles(run)
	if err != nil {
		t.Fatal(err)
	}
	if err := files.Dir(id); err != nil {
		t.Fatal(err)
	}
	// Remove only this randomly allocated fixture, never production runs.
	t.Cleanup(func() {
		if filepath.Dir(private(run)) == files.Root && filepath.Base(private(run)) == id {
			_ = os.RemoveAll(private(run))
		}
	})
	uid, sid, err := OwnerIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "examples", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	s := State{Version: 1, Phase: "stopped", Manifest: Manifest{Version: 1, Owner: uid, OwnerSID: sid, Config: cfg, Created: time.Now()}, Windows: &WindowsState{PublicRun: run, BootID: "cleanup-fixture"}}
	if err := initializeStateStorage(run, &s); err != nil {
		t.Fatal(err)
	}
	if err := save(run, &s); err != nil {
		t.Fatal(err)
	}
	if err := securefile.Bytes(filepath.Join(run, "STOP"), nil); err != nil {
		t.Fatal(err)
	}
	journal := winstate.Journal{Version: 1, BootID: s.Windows.BootID, Stopping: true}
	writeJournal := func() {
		t.Helper()
		if err := files.Write(filepath.Join(id, "network.json"), journal); err != nil {
			t.Fatal(err)
		}
	}
	writeJournal()
	if err := cleanupEligible(run); err != nil {
		t.Fatal(err)
	}
	s.Phase = "recovery_failed"
	if err := save(run, &s); err != nil {
		t.Fatal(err)
	}
	if err := cleanupEligible(run); err == nil {
		t.Fatal("accepted failed recovery")
	}
	s.Phase = "stopped"
	s.Runner, err = platform.Process(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := save(run, &s); err != nil {
		t.Fatal(err)
	}
	if err := cleanupEligible(run); err == nil {
		t.Fatal("accepted running coordinator")
	}
	s.Runner = platform.Identity{}
	if err := save(run, &s); err != nil {
		t.Fatal(err)
	}
	journal.Guards = []winstate.GuardChange{{State: "applied"}}
	writeJournal()
	if err := cleanupEligible(run); err == nil {
		t.Fatal("accepted unrestored WFP")
	}
	journal.Guards = nil
	writeJournal()
	ref := filepath.Join(profile, "current.json")
	if err := securefile.Write(ref, map[string]string{"run": run}); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupRun(profile, run, true); err == nil {
		t.Fatal("accepted current run")
	}
	if err := os.Remove(ref); err != nil {
		t.Fatal(err)
	}
	if err := securefile.Bytes(filepath.Join(run, "vpn-private.log"), []byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := files.Bytes(filepath.Join(id, "vpn-private.log"), []byte("payload")); err != nil {
		t.Fatal(err)
	}
	// Full native orchestration is possible only when no real coordinator holds
	// active.lock; this fixture never stops it or rewrites active.json.
	unlock, err := cleanupGlobalLock(run)
	if err != nil {
		t.Log("full cleanup unavailable while native coordinator is active:", err)
		return
	}
	unlock()
	r, err := CleanupRun(profile, run, false)
	if err != nil || r.Applied || r.Files != 2 {
		t.Fatal("preview", r, err)
	}
	r, err = CleanupRun(profile, run, true)
	if err != nil || !r.Applied || !r.RecoveryRetained {
		t.Fatal("apply", r, err)
	}
	if _, err := load(run); err != nil {
		t.Fatal("lost privileged evidence", err)
	}
	if _, err := os.Stat(filepath.Join(run, "vpn-private.log")); !os.IsNotExist(err) {
		t.Fatal("public payload retained", err)
	}
	if _, err := files.Read(filepath.Join(id, "vpn-private.log"), 32); !os.IsNotExist(err) {
		t.Fatal("private payload retained", err)
	}
	r, err = CleanupRun(profile, run, true)
	if err != nil || r.Files != 0 {
		t.Fatal("retry", r, err)
	}
}
