//go:build darwin

package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/securefile"
)

func private(run string) string {
	return filepath.Join("/Library/Application Support/NetLaunch", filepath.Base(run))
}
func readVPNLog(run, name string) ([]byte, error) {
	return securefile.ReadTail(filepath.Join(private(run), name), 128<<10, true)
}
func validateRoot(run string) error {
	if os.Geteuid() != 0 {
		return errors.New("native administrator authorization is required")
	}
	if e := ValidateRun(run); e != nil {
		return e
	}
	for _, p := range []string{filepath.Dir(private(run)), private(run), filepath.Join(private(run), "state.json")} {
		i, e := os.Lstat(p)
		if e != nil {
			return e
		}
		s, ok := i.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != 0 || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm()&0077 != 0 {
			return errors.New("recovery state identity or owner changed")
		}
	}
	return nil
}
func load(run string) (State, error) {
	if e := validateRoot(run); e != nil {
		return State{}, e
	}
	raw, e := readRunFile(run, "state.json", 4<<20)
	if e != nil {
		return State{}, e
	}
	return decodeState(raw, func() ([]byte, error) { return readRunFile(run, "run-spec.json", 2<<20) })
}
func save(run string, s *State) error {
	s.Updated = time.Now()
	record, e := stateRecord(s)
	if e != nil {
		return e
	}
	if e := securefile.Write(filepath.Join(private(run), "state.json"), record); e != nil {
		return e
	}
	out := publicStatus(*s, s.Updated)
	p := filepath.Join(run, "status.json")
	if e := securefile.Write(p, out); e != nil {
		return e
	}
	return os.Chown(p, s.Manifest.Owner, -1)
}

func readRunFile(run, name string, limit int64) ([]byte, error) {
	return securefile.Read(filepath.Join(private(run), name), limit, true)
}
func writeRunFile(run, name string, value any) error {
	return securefile.Write(filepath.Join(private(run), name), value)
}
func lockRunFile(run, name string, limit time.Duration) (func(), error) {
	return securefile.Lock(filepath.Join(private(run), name), limit)
}
func update(run string, fn func(*State) error) error {
	if e := validateRoot(run); e != nil {
		return e
	}
	unlock, e := securefile.Lock(filepath.Join(private(run), "state.lock"), 30*time.Second)
	if e != nil {
		return e
	}
	defer unlock()
	s, e := load(run)
	if e != nil {
		return e
	}
	before := s
	if e = fn(&s); e != nil {
		return e
	}
	invalidateChannelHealth(before, &s)
	return save(run, &s)
}
func guard(run string, s *State) error {
	if _, e := os.Stat(filepath.Join(run, "STOP")); e == nil || s.Phase == "stopping" || s.Phase == "stopped" || s.Phase == "recovery_failed" {
		return errors.New("stop requested")
	}
	return nil
}
func legacyPulse(run string) error {
	return update(run, func(s *State) error {
		if e := guard(run, s); e != nil {
			return e
		}
		if s.Watcher.PID > 0 {
			id, e := platform.Process(s.Watcher.PID)
			if e != nil || id != s.Watcher {
				return errors.New("independent watchdog disappeared")
			}
		}
		s.Heartbeat = time.Now()
		return nil
	})
}

func verifyPulseProcesses(s State) error {
	me, err := platform.Process(os.Getpid())
	if err != nil || me != s.Runner {
		return errors.New("unpublished coordinator cannot update heartbeat")
	}
	if s.Watcher.PID > 0 {
		actual, err := platform.Process(s.Watcher.PID)
		if err != nil || actual != s.Watcher {
			return errors.New("independent watchdog disappeared")
		}
	}
	return nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func Launch(action, run string) error {
	if e := ValidateRun(run); e != nil {
		return e
	}
	if action != "serve" && action != "recover" {
		return errors.New("invalid privileged action")
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	if action == "serve" {
		m, e := ReadManifest(run)
		if e != nil {
			return e
		}
		self = m.Executable
	}
	line := "umask 077; cd /private/tmp && " + shellQuote(self) + " _" + action + " --run " + shellQuote(run)
	if action == "recover" {
		frozen := shellQuote(filepath.Join(private(run), "netlaunch"))
		line = "umask 077; cd /private/tmp && if [ -x " + frozen + " ]; then " + frozen + " _recover --run " + shellQuote(run) + "; else " + shellQuote(self) + " _recover --run " + shellQuote(run) + "; fi"
	}
	if action == "serve" {
		line += " >/dev/null 2>&1 </dev/null &"
	}
	script := "do shell script " + strconv.Quote(line) + " with administrator privileges"
	cmd := exec.Command("/usr/bin/osascript", "-e", script)
	if e = cmd.Run(); e != nil {
		return errors.New("native authorization or launch did not complete")
	}
	return nil
}

func spawn(run, role string, args []string, exits *childExitTracker) (Child, error) {
	var result Child
	e := update(run, func(s *State) error {
		if e := guard(run, s); e != nil {
			return e
		}
		index := len(s.Children)
		m := s.Manifest
		gateArgs := []string{m.Executable, "_child", "--run", run, "--index", strconv.Itoa(index)}
		logName := fmt.Sprintf("%s-%d-private.log", role, index)
		log, e := os.OpenFile(filepath.Join(private(run), logName), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		defer log.Close()
		cmd := exec.Command(gateArgs[0], gateArgs[1:]...)
		cmd.Stdin = nil
		cmd.Stdout = log
		cmd.Stderr = log
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if e = cmd.Start(); e != nil {
			return errors.New("child launch failed")
		}
		id, e := platform.Process(cmd.Process.Pid)
		if e != nil || id.PID == 0 {
			go func() { _ = cmd.Wait() }()
			return errors.New("child identity unavailable")
		}
		result = Child{Role: role, PID: id.PID, Birth: id.Birth, Args: args, GateArgs: gateArgs, Released: false, LogName: logName}
		launched := result
		exits.trackExitReason(role, id, func() (uint32, string, error) {
			err := cmd.Wait()
			var exit *exec.ExitError
			var code uint32
			if errors.As(err, &exit) {
				code, err = uint32(exit.ExitCode()), nil
			}
			reason := "vpn_process_exited"
			if role == "vpn" {
				reason = vpnAttemptFailure(run, launched)
			}
			return code, reason, err
		})
		s.Children = append(s.Children, result)
		return nil
	})
	if e != nil {
		return result, e
	}
	e = update(run, func(s *State) error {
		if e := guard(run, s); e != nil {
			return e
		}
		for i := range s.Children {
			if s.Children[i].PID == result.PID {
				s.Children[i].Released = true
				return nil
			}
		}
		return errors.New("child journal missing")
	})
	return result, e
}

func child(run string, index int) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s, e := load(run)
		if e == nil && index >= 0 && index < len(s.Children) {
			c := s.Children[index]
			if c.PID != os.Getpid() {
				return errors.New("child journal identity mismatch")
			}
			if e = guard(run, &s); e != nil {
				return e
			}
			if c.Released {
				if c.Role == "vpn" {
					var a struct {
						Cookie string `json:"cookie"`
					}
					if e = readJSON(filepath.Join(private(run), "auth.json"), &a); e != nil {
						return e
					}
					// An unlinked file avoids blocking on a full pipe before exec.
					r, e := os.CreateTemp(private(run), ".cookie-")
					if e != nil {
						return e
					}
					if e = os.Remove(r.Name()); e != nil {
						r.Close()
						return e
					}
					if _, e = r.WriteString(a.Cookie + "\n"); e != nil {
						r.Close()
						return e
					}
					if _, e = r.Seek(0, 0); e != nil {
						r.Close()
						return e
					}
					if e = syscall.Dup2(int(r.Fd()), 0); e != nil {
						r.Close()
						return e
					}
					r.Close()
				}
				env := append(os.Environ(), "OPENSSL_CONF=/dev/null")
				return syscall.Exec(c.Args[0], c.Args, env)
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return errors.New("child launch gate expired")
}
func alive(c Child) (bool, error) {
	i, e := platform.Process(c.PID)
	if e != nil || i.PID == 0 {
		return false, e
	}
	if i.Birth != c.Birth {
		return false, nil // the original process is gone; never signal the replacement
	}
	for _, args := range [][]string{c.Args, c.GateArgs} {
		if len(args) > 0 && i.Executable == args[0] && i.Command == strings.Join(args, " ") {
			return true, nil
		}
	}
	return false, errors.New("owned process changed command identity")
}
func stopChild(c Child) error {
	ok, e := alive(c)
	if e != nil || !ok {
		return e
	}
	sig := syscall.SIGTERM
	if c.Role == "vpn" {
		sig = syscall.SIGHUP
	}
	if e = syscall.Kill(c.PID, sig); e != nil && !errors.Is(e, syscall.ESRCH) {
		return e
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		id, e := platform.Process(c.PID)
		if e == nil && (id.PID == 0 || id.Birth != c.Birth) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("owned %s did not exit; no forced kill used", c.Role)
}

// Called only after acquiring recovery.lock. The recovering coordinator itself
// is excluded; another process is killed only after full recorded identity checks.
func stopCoordinator(expected platform.Identity) error {
	if expected.PID == os.Getpid() {
		return nil
	}
	if expected.PID < 2 || expected.Birth == "" || expected.Command == "" || expected.Executable == "" {
		return errors.New("coordinator identity is incomplete")
	}
	actual, err := platform.Process(expected.PID)
	if err != nil {
		return err
	}
	if actual.PID == 0 || actual.Birth != expected.Birth {
		return nil
	}
	if actual != expected {
		return errors.New("coordinator identity changed; recovery did not signal it")
	}
	if err := syscall.Kill(expected.PID, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		actual, err = platform.Process(expected.PID)
		if err != nil {
			return err
		}
		if actual.PID == 0 || actual.Birth != expected.Birth {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("owned coordinator did not exit; preserve recovery files")
}
func Internal(action, run string) error {
	if os.Geteuid() != 0 {
		return errors.New("native administrator authorization is required")
	}
	switch action {
	case "serve":
		return serve(run)
	case "watch":
		return watch(run)
	case "recover":
		return recoverRun(run, "local_stop")
	case "hook":
		return hook(run)
	}
	return errors.New("unknown internal action")
}
func ChildMain(run string, index int) error { return child(run, index) }
func native(ctx context.Context, path string, args ...string) error {
	_, e := platform.Command(ctx, path, args...)
	return e
}

func validateOwner(run string, m Manifest) error {
	if m.Owner < 1 || m.OwnerSID != "" {
		return errors.New("invalid macOS run owner")
	}
	owner := m.Owner
	i, e := os.Lstat(run)
	if e != nil {
		return e
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || int(s.Uid) != owner {
		return errors.New("run owner does not match manifest")
	}
	return nil
}

func OwnerIdentity() (int, string, error) {
	if os.Getuid() < 1 {
		return 0, "", errors.New("launch from an ordinary user session")
	}
	return os.Getuid(), "", nil
}
