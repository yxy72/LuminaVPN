//go:build windows

package engine

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/windows"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/testutil"
	"netlaunch/internal/winnet"
	"netlaunch/internal/winproc"
	"netlaunch/internal/winstate"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This launches the production frozen-process/watchdog chain with an empty
// journal. The normal CLI build keeps _run gated; no VPN, runtime, auth,
// nodes, or global active-run reference is installed by this fixture.
func frozenWatcherFixture(t *testing.T, versions ...int) string {
	t.Helper()
	cli := os.Getenv("NETLAUNCH_TEST_CLI")
	if cli == "" {
		t.Skip("set NETLAUNCH_TEST_CLI to the built Windows netlaunch executable")
	}
	run, e := securefile.TempDir(testutil.PrivateTempDir(t), "netlaunch-")
	if e != nil {
		t.Fatal(e)
	}
	files, id, e := winFiles(run)
	if e != nil {
		t.Fatal(e)
	}
	if e = files.Dir(id); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(cli)
	if e != nil {
		t.Fatal(e)
	}
	if e = files.Bytes(filepath.Join(id, "netlaunch.exe"), b); e != nil {
		t.Fatal(e)
	}
	b, e = os.ReadFile(filepath.Join("..", "..", "examples", "policy.json"))
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := policy.Decode(b)
	if e != nil {
		t.Fatal(e)
	}
	uid, sid, e := OwnerIdentity()
	if e != nil {
		t.Fatal(e)
	}
	m := Manifest{Version: 1, Owner: uid, OwnerSID: sid, Config: cfg, Executable: frozenSelf(run), Created: time.Now(), Binding: policy.Binding{VPN: "NL-NoNetwork-VPN-" + id, TUN: "NL-NoNetwork-TUN-" + id}}
	m.ValidationTimeout = 10 * time.Second
	if e = securefile.Write(filepath.Join(run, "manifest.json"), m); e != nil {
		t.Fatal(e)
	}
	boot, e := winnet.BootID()
	if e != nil {
		t.Fatal(e)
	}
	s := State{Version: 1, Manifest: m, Phase: "preparing", Heartbeat: time.Now(), Windows: &WindowsState{BootID: boot, PublicRun: run}}
	if len(versions) == 0 || versions[0] == currentStateVersion {
		if e = initializeStateStorage(run, &s); e != nil {
			t.Fatal(e)
		}
	}
	if e = save(run, &s); e != nil {
		t.Fatal(e)
	}
	if e = files.Write(filepath.Join(id, "network.json"), winstate.Journal{Version: 1, BootID: boot}); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		s, err := load(run)
		if err != nil || s.Runner.PID == 0 {
			return
		}
		if s.Phase != "stopped" {
			if err := recoverRun(run, "test_cleanup"); err != nil {
				t.Error(err)
			}
		}
		if s.Watcher.PID > 0 {
			if err := awaitProcessExit(s.Watcher, 10*time.Second); err != nil {
				t.Error(err)
			}
		}
	})
	return run
}

func TestFrozenCoordinatorHasIndependentReadyWatcher(t *testing.T) {
	for _, version := range []int{1, currentStateVersion} {
		t.Run(fmt.Sprintf("state_v%d", version), func(t *testing.T) { checkFrozenRecoveryVersion(t, version) })
	}
}

func checkFrozenRecoveryVersion(t *testing.T, version int) {
	run := frozenWatcherFixture(t, version)
	_, id, e := winFiles(run)
	if e != nil {
		t.Fatal(e)
	}
	if e = startFrozenCoordinator(run); e != nil {
		t.Fatal(e)
	}
	var ready platform.Identity
	if e = winRead(run, "watcher-ready.json", &ready); e != nil {
		t.Fatal("coordinator resumed without readiness", e)
	}
	deadline := time.Now().Add(15 * time.Second)
	var s State
	for {
		s, e = load(run)
		if e != nil {
			t.Fatal(e)
		}
		if s.Phase == "stopped" {
			break
		}
		if s.Phase == "recovery_failed" || time.Now().After(deadline) {
			t.Fatal("independent empty recovery did not complete", s.Phase, s.Error)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !sameProcess(ready, s.Watcher) || s.Runner.PID == s.Watcher.PID || s.RecoveryReason != "coordinator_exited" {
		t.Fatal("missing independent recovery identity or reason")
	}
	var j winstate.Journal
	if e = winRead(run, "network.json", &j); e != nil {
		t.Fatal(e)
	}
	if !j.Stopping || len(j.Routes)+len(j.DNS)+len(j.Pairs)+len(j.Guards)+len(j.Addresses)+len(j.MTU) != 0 || len(s.Children) != 0 {
		t.Fatal("empty recovery changed network state")
	}
	t.Log("production frozen coordinator/watchdog recovery completed:", id)
}

func TestHeartbeatWritesDoNotRewriteOrLockRecoverySnapshot(t *testing.T) {
	run := frozenWatcherFixture(t)
	me, err := platform.Process(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := update(run, func(s *State) error { s.Runner = me; return nil }); err != nil {
		t.Fatal(err)
	}
	before, err := readRunFile(run, "state.json", 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := readRunFile(run, "run-spec.json", 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := lockRunFile(run, "state.lock", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// The native snapshot lock is deliberately held while heartbeat advances.
	err = pulse(run)
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := alivePulse(run); err != nil {
		t.Fatal(err)
	}
	after, err := readRunFile(run, "state.json", 4<<20)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("heartbeat rewrote recovery state", err)
	}
	afterSpec, err := readRunFile(run, "run-spec.json", 2<<20)
	if err != nil || !bytes.Equal(spec, afterSpec) {
		t.Fatal("heartbeat rewrote immutable spec", err)
	}
	s, err := load(run)
	if err != nil {
		t.Fatal(err)
	}
	m, err := readMonitor(run, s)
	if err != nil || !m.ProgressAt.After(s.Heartbeat) || m.AliveAt.Before(m.ProgressAt) {
		t.Fatal("monitor did not advance", err)
	}
}

func TestStateLockHolderHelper(t *testing.T) {
	run := os.Getenv("NETLAUNCH_TEST_STATE_LOCK_RUN")
	if run == "" {
		t.Skip("owned state-lock fixture subprocess only")
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := readRunFile(run, "fixture-lock-go.json", 4096); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture lock permission missing")
		}
		time.Sleep(20 * time.Millisecond)
	}
	unlock, err := lockRunFile(run, "state.lock", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := writeRunFile(run, "fixture-lock-ready.json", true); err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Second)
	t.Fatal("watcher did not terminate owned stalled coordinator")
}

func TestProductionWatcherRecoversStalledCoordinatorHoldingStateLock(t *testing.T) {
	run := frozenWatcherFixture(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child, err := winproc.StartIndependent(winproc.Spec{Args: []string{self, "-test.run=^TestStateLockHolderHelper$"}, Environment: append(os.Environ(), "NETLAUNCH_TEST_STATE_LOCK_RUN="+run)}, func(who platform.Identity) error {
		return update(run, func(s *State) error {
			s.Runner = who
			s.Heartbeat = time.Now()
			s.LastReady = s.Heartbeat
			s.Phase = "ready"
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _, _ = child.Wait(); close(done) }()
	defer func() {
		_ = platform.StopIdentity(child.Identity)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("owned helper did not exit")
		}
	}()
	if err := startWatcher(run); err != nil {
		t.Fatal(err)
	}
	if err := writeRunFile(run, "fixture-lock-go.json", true); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := readRunFile(run, "fixture-lock-ready.json", 4096); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned helper did not acquire state lock")
		}
		time.Sleep(20 * time.Millisecond)
	}
	s, err := load(run)
	if err != nil {
		t.Fatal(err)
	}
	m := baselineMonitor(s)
	m.AliveAt, m.ProgressAt = time.Now(), time.Now().Add(-40*time.Second)
	if err := writeRunFile(run, "heartbeat.json", m); err != nil {
		t.Fatal(err)
	}
	for {
		s, err = load(run)
		if err != nil {
			t.Fatal(err)
		}
		if s.Phase == "stopped" {
			break
		}
		if time.Now().After(deadline) || s.Phase == "recovery_failed" {
			t.Fatal("watcher blocked behind stalled state lock", s.Phase)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if s.RecoveryReason != "coordinator_stalled" {
		t.Fatal(s.RecoveryReason)
	}
	var journal winstate.Journal
	if err := winRead(run, "network.json", &journal); err != nil || !journal.Stopping || len(journal.Routes)+len(journal.DNS)+len(journal.Pairs)+len(journal.Guards)+len(journal.Addresses)+len(journal.MTU) != 0 {
		t.Fatal("empty recovery changed network", err)
	}
}

func TestProductionWatcherHonorsHardDeadline(t *testing.T) {
	run := frozenWatcherFixture(t)
	system, e := windows.GetSystemDirectory()
	if e != nil {
		t.Fatal(e)
	}
	in, writer, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer in.Close()
	defer writer.Close()
	out, e := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer out.Close()
	// A known owned process blocks on an empty stdin pipe. No network or
	// grandchildren are involved; the real production watcher must stop it.
	child, e := winproc.StartIndependent(winproc.Spec{Args: []string{filepath.Join(system, "cmd.exe"), "/d", "/c", "set /p LUMINA_TEST_WAIT="}, Stdin: in, Stdout: out, Stderr: out}, func(who platform.Identity) error {
		return update(run, func(s *State) error {
			s.Runner = who
			s.Windows.ValidationDeadline = time.Now().Add(2 * time.Second)
			return nil
		})
	})
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() { _, _ = child.Wait(); close(done) }()
	defer func() {
		_ = platform.StopIdentity(child.Identity)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("owned waiting child did not exit")
		}
	}()
	if e = startWatcher(run); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		s, e := load(run)
		if e != nil {
			t.Fatal(e)
		}
		if s.Phase == "stopped" {
			if s.RecoveryReason != "validation_deadline" {
				t.Fatal("watcher did not enforce its deadline", s.RecoveryReason)
			}
			break
		}
		if s.Phase == "recovery_failed" || time.Now().After(deadline) {
			t.Fatal("deadline recovery did not finish", s.Phase)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
