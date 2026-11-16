//go:build darwin

package engine

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"netlaunch/internal/platform"
	"netlaunch/internal/securefile"
	"netlaunch/internal/testutil"
)

func testDarwinOwnershipStore(t *testing.T) darwinOwnershipStore {
	t.Helper()
	return darwinOwnershipStore{root: testutil.PrivateTempDir(t), uid: uint32(os.Geteuid())}
}

func testDarwinOwner(run string) darwinRunOwner {
	return darwinRunOwner{
		Version: 1, Run: run, UID: 501, Device: 1, Inode: 1, Spec: strings.Repeat("ab", 32),
		Runner: platform.Identity{PID: 15, Birth: "fixture", Executable: "/fixture/bin", Command: "fixture command"},
	}
}

func TestDarwinOwnershipSurvivesCoordinatorLockRelease(t *testing.T) {
	store := testDarwinOwnershipStore(t)
	owner := testDarwinOwner(filepath.Join(t.TempDir(), "netlaunch-one"))
	other := testDarwinOwner(filepath.Join(t.TempDir(), "netlaunch-two"))
	dir := filepath.Join(store.root, filepath.Base(owner.Run))
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	firstLock, err := store.lock()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.claim(owner); err != nil {
		firstLock()
		t.Fatal(err)
	}
	firstLock()

	nextLock, err := store.lock()
	if err != nil {
		t.Fatal(err)
	}
	defer nextLock()
	if err := store.claim(other); err == nil {
		t.Fatal("lost coordinator lock admitted another owner")
	}
	if err := store.seal(other); err == nil {
		t.Fatal("another run released the original owner")
	}
	replaced := owner
	replaced.Inode++
	if err := store.seal(replaced); err == nil {
		t.Fatal("a replaced public run directory released the original owner")
	}
	if got, err := store.active(); err != nil || got != owner {
		t.Fatalf("owner changed after a refused recovery: %v", err)
	}

	// A failed receipt leaves the global fence available for a same-run retry.
	receipt := filepath.Join(dir, darwinRecoveryFile)
	if err := os.Mkdir(receipt, 0700); err != nil {
		t.Fatal(err)
	}
	if err := store.seal(owner); err == nil {
		t.Fatal("released owner without a durable receipt")
	}
	if got, err := store.active(); err != nil || got != owner {
		t.Fatalf("owner missing after failed receipt: %v", err)
	}
	if err := os.Remove(receipt); err != nil {
		t.Fatal(err)
	}
	if err := store.seal(owner); err != nil {
		t.Fatal(err)
	}
	got, err := store.proof(owner.Run)
	if err != nil || got.Owner != owner || got.RestoredAt.IsZero() {
		t.Fatalf("receipt not bound to released owner: %v", err)
	}
	if _, err := store.active(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("global owner remained after confirmed release: %v", err)
	}
	if err := store.claim(other); err != nil {
		t.Fatalf("a later profile could not acquire the released fence: %v", err)
	}
}

func TestDarwinStartupFencesUnrestoredLegacyJournal(t *testing.T) {
	store := testDarwinOwnershipStore(t)
	dir := filepath.Join(store.root, "netlaunch-legacy")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := store.requireLegacyIdle(); err != nil {
		t.Fatalf("pre-journal directory may not have touched resources: %v", err)
	}
	for _, phase := range []string{"preparing", "ready", "stopping", "recovery_failed", "stopped"} {
		if err := securefile.Write(filepath.Join(dir, "state.json"), State{Version: 1, Phase: phase}); err != nil {
			t.Fatal(err)
		}
		if err := store.requireLegacyIdle(); (err == nil) != (phase == "stopped") {
			t.Fatalf("unexpected startup authority for legacy phase %s: %v", phase, err)
		}
	}
	if err := os.Chmod(filepath.Join(dir, "state.json"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := store.requireLegacyIdle(); err == nil {
		t.Fatal("user-writable stopped journal authorized startup")
	}
}

func TestDarwinLegacyStopOnlyGetsReceiptAfterNewNativeEvidence(t *testing.T) {
	store := testDarwinOwnershipStore(t)
	run := filepath.Join(t.TempDir(), "netlaunch-legacy")
	owner := testDarwinOwner(run)
	owner.Runner.Command = strings.Join([]string{owner.Runner.Executable, "_serve", "--run", run}, " ")
	dir := filepath.Join(store.root, filepath.Base(run))
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	status := State{Version: 1, Phase: "stopped"}
	if err := securefile.Write(filepath.Join(dir, "state.json"), status); err != nil {
		t.Fatal(err)
	}
	unlock, err := store.lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	evidence := errors.New("an old route is still present")
	if err := store.attestLegacyStop(status, owner, func(State) error { return evidence }); !errors.Is(err, evidence) {
		t.Fatalf("native evidence was not required: %v", err)
	}
	if _, err := store.proof(run); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("receipt was published despite a failed check: %v", err)
	}
	active, err := securefile.Lock(filepath.Join(store.root, "active.lock"), 0)
	if err != nil {
		t.Fatal(err)
	}
	locked := store.attestLegacyStop(status, owner, func(State) error {
		t.Fatal("resource check raced with another coordinator")
		return nil
	})
	active()
	if locked == nil {
		t.Fatal("published legacy receipt while a coordinator was active")
	}
	if err := store.attestLegacyStop(status, owner, func(State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if proof, err := store.proof(run); err != nil || proof.Owner != owner {
		t.Fatalf("native proof did not bind the legacy run: %v", err)
	}
}

func TestDarwinRecoveryProcessAbsenceUsesNativeEvidence(t *testing.T) {
	child := exec.Command("/bin/sleep", "15")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	id, err := platform.Process(child.Process.Pid)
	if err != nil || id.PID == 0 {
		t.Fatal("fixture identity unavailable", err)
	}
	if err := darwinProcessGone(id.PID, id.Birth); err == nil {
		t.Fatal("live owned process reported absent")
	}
	if err := darwinProcessGone(id.PID, "different birth"); err != nil {
		t.Fatal("a reused PID should not be treated as the old process", err)
	}
	_ = child.Process.Kill()
	_ = child.Wait()
	if err := darwinProcessGone(id.PID, id.Birth); err != nil {
		t.Fatal("process exit not confirmed", err)
	}
}
