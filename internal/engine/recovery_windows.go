//go:build windows

package engine

import (
	"errors"
	"golang.org/x/sys/windows"
	"netlaunch/internal/platform"
	"netlaunch/internal/securefile"
	"netlaunch/internal/selector"
	"netlaunch/internal/winnet"
	"netlaunch/internal/winproc"
	"os"
	"path/filepath"
	"time"
)

func watch(run string) error {
	s, e := load(run)
	if e != nil {
		return e
	}
	me, e := platform.Process(os.Getpid())
	if e != nil {
		return e
	}
	if !sameProcess(s.Watcher, me) || !sameExecutable(me.Executable, frozenSelf(run)) {
		return errors.New("unpublished or mutable watchdog")
	}
	deadline := s.Windows.ValidationDeadline
	if windowsFlowIsolationReady && deadline.IsZero() {
		return errors.New("validation watchdog has no hard deadline")
	}
	power, e := winnet.WatchPower()
	if e != nil {
		return recoverRun(run, "watchdog_power_monitor_failed")
	}
	defer power.Close()
	epoch, _ := power.Epoch()
	if e = winWrite(run, "watcher-ready.json", me); e != nil {
		return e
	}
	var grace time.Time
	for {
		s, e := load(run)
		if e != nil {
			return e
		}
		if s.Phase == "stopped" || s.Phase == "recovery_failed" {
			return nil
		}
		reason := ""
		if !s.Windows.ValidationDeadline.Equal(deadline) {
			reason = "validation_deadline_changed"
		} else if !deadline.IsZero() && !time.Now().Before(deadline) {
			reason = "validation_deadline"
		}
		if _, e = os.Lstat(filepath.Join(run, "STOP")); e == nil {
			reason = "user_stop"
		} else if !errors.Is(e, os.ErrNotExist) {
			reason = "stop_marker_unreadable"
		}
		actual, e := platform.Process(s.Runner.PID)
		if e != nil || !sameProcess(s.Runner, actual) {
			reason = "coordinator_exited"
		}
		now, awake := power.Epoch()
		if now != epoch {
			epoch = now
			grace = time.Now().Add(35 * time.Second)
		}
		if awake && time.Since(s.Heartbeat) > 35*time.Second && !time.Now().Before(grace) {
			reason = "coordinator_unresponsive"
		}
		if reason != "" {
			return recoverRun(run, reason)
		}
		// A stalled coordinator cannot leave expired native grants indefinitely.
		// The independent watchdog stops the owned jobs before rolling them back.
		if awake && leaseExpired(s) && time.Since(s.Heartbeat) > 5*time.Second {
			return recoverRun(run, "lease_guard_expired")
		}
		time.Sleep(time.Second)
	}
}
func recoverRun(run, reason string) error {
	if e := securefile.RequireAdmin(); e != nil {
		return e
	}
	if e := ValidateRun(run); e != nil {
		return e
	}
	if e := securefile.Bytes(filepath.Join(run, "STOP"), nil); e != nil {
		return e
	}
	files, id, e := winFiles(run)
	if e != nil {
		return e
	}
	if _, e = files.Read(filepath.Join(id, "state.json"), 4<<20); errors.Is(e, os.ErrNotExist) {
		return cancelledStatus(run)
	} else if e != nil {
		return e
	}
	// Explicit recovery starts in the staged public launcher after UAC. Delegate
	// to the frozen binary so later public-file edits do not change recovery.
	self, e := os.Executable()
	if e != nil {
		return e
	}
	if reason == "explicit_recovery" && !sameExecutable(self, frozenSelf(run)) {
		if e = files.Check(filepath.Join(id, "netlaunch.exe"), false); e != nil {
			return e
		}
		p, e := winproc.StartIndependent(winproc.Spec{Args: []string{frozenSelf(run), "_recover", "--run", run}, Directory: private(run)}, func(platform.Identity) error { return nil })
		if e != nil {
			return e
		}
		code, e := p.Wait()
		if e != nil {
			return e
		}
		if code != 0 {
			return errors.New("frozen recovery returned an error")
		}
		return nil
	}
	unlock, e := files.Lock(filepath.Join(id, "recovery.lock"), 2*time.Minute)
	if e != nil {
		return e
	}
	defer unlock()
	s, e := load(run)
	if e != nil {
		return e
	}
	if s.Phase == "stopped" {
		return nil
	}
	if e = update(run, func(s *State) error {
		s.Phase = "stopping"
		s.VPN.Bootstrap = false
		s.Windows.LaunchToken = ""
		s.RecoveryReason = reason
		return nil
	}); e != nil {
		return e
	}
	failed := func(err error) error {
		_ = update(run, func(s *State) error {
			s.Phase = "recovery_failed"
			s.Error = "restore_incomplete_run_down_again"
			return nil
		})
		return err
	}
	if s.Runner.PID != os.Getpid() {
		current, e := platform.Process(s.Runner.PID)
		if e != nil {
			return failed(e)
		}
		if sameProcess(s.Runner, current) {
			if e = platform.StopIdentity(s.Runner); e != nil {
				return failed(e)
			}
			if e = awaitProcessExit(s.Runner, 12*time.Second); e != nil {
				return failed(e)
			}
		}
	}
	// Coordinator exit closes both kill-on-close jobs, including OpenConnect's
	// script descendants. Per-child handles/identities provide bounded readback.
	s, e = load(run)
	if e != nil {
		return failed(e)
	}
	for _, role := range []string{"core", "vpn"} {
		for _, child := range s.Children {
			if child.Role == role {
				if e = stopChild(child); e != nil {
					return failed(e)
				}
			}
		}
	}
	m, e := networkManager(run)
	if e != nil {
		return failed(e)
	}
	if _, e = m.Store.Load(); e != nil {
		// No child or watchdog can start before this journal is created.
		if !errors.Is(e, os.ErrNotExist) || s.Watcher.PID != 0 || len(s.Children) != 0 {
			return failed(e)
		}
	} else {
		until := time.Now().Add(10 * time.Second)
		for {
			e = m.Recover()
			if e == nil {
				break
			}
			// Windows can still enumerate a disappearing Wintun device after
			// its IPv4 row has gone. Retry exact journal recovery; never treat
			// a missing row as permission to skip ownership verification.
			if time.Now().After(until) || (!errors.Is(e, windows.ERROR_NOT_FOUND) && !errors.Is(e, windows.ERROR_FILE_NOT_FOUND)) {
				return failed(e)
			}
			time.Sleep(time.Second)
		}
	}
	if e = VerifyOwnedInterfaces(run); e != nil {
		return failed(e)
	}
	if e = update(run, func(s *State) error {
		s.Phase = "stopped"
		s.Personal = selector.Reject
		s.Error = ""
		s.Leases = nil
		return nil
	}); e != nil {
		return e
	}
	for _, name := range []string{"auth.json", "nodes.json", "auth-refresh.json", "core.json"} {
		// Administrator storage is only writable by this elevated token. Public
		// secrets were never needed after freezing and are removed as well.
		_ = os.Remove(filepath.Join(private(run), name))
		_ = os.Remove(filepath.Join(run, name))
	}
	return nil
}
func VerifyOwnedInterfaces(run string) error {
	s, e := load(run)
	if e != nil {
		return e
	}
	rows, e := winnet.Routes()
	if e != nil {
		return e
	}
	for _, r := range rows {
		a := s.Windows.TUNAdapter
		if a.LUID != 0 && r.InterfaceLUID == a.LUID && r.InterfaceIndex == a.Index && (r.Prefix == "0.0.0.0/0" || r.Prefix == "0.0.0.0/1" || r.Prefix == "128.0.0.0/1") {
			return errors.New("candidate TUN still captures traffic")
		}
	}
	// Wintun may retain an inactive adapter. No global adapter deletion is used;
	// an active candidate after its owning job exits is an incomplete recovery.
	adapters, e := winnet.Adapters()
	if e != nil {
		return e
	}
	for _, a := range adapters {
		if (a.Name == s.Manifest.Binding.VPN || a.Name == s.Manifest.Binding.TUN) && a.Up {
			return errors.New("candidate virtual adapter remains active")
		}
	}
	return nil
}
