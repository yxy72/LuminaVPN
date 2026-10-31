//go:build windows

package engine

import (
	"encoding/json"
	"errors"
	"netlaunch/internal/platform"
	"netlaunch/internal/securefile"
	"netlaunch/internal/selector"
	"netlaunch/internal/winstate"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var windowsRunID = regexp.MustCompile(`^netlaunch-[a-f0-9]{32}$`)

func winFiles(run string) (securefile.AdminStore, string, error) {
	if e := ValidateRun(run); e != nil {
		return securefile.AdminStore{}, "", e
	}
	id := filepath.Base(run)
	if !windowsRunID.MatchString(id) {
		return securefile.AdminStore{}, "", errors.New("invalid Windows run identifier")
	}
	files, e := securefile.OpenAdminStore()
	return files, id, e
}
func private(run string) string {
	root, e := securefile.AdminLocation()
	if e != nil {
		return ""
	}
	return filepath.Join(root, filepath.Base(run))
}
func winRead(run, name string, value any) error {
	files, id, e := winFiles(run)
	if e != nil {
		return e
	}
	b, e := files.Read(filepath.Join(id, name), 4<<20)
	if e != nil {
		return e
	}
	if json.Unmarshal(b, value) != nil {
		return errors.New("invalid administrator state")
	}
	return nil
}
func readVPNLog(run, name string) ([]byte, error) {
	files, id, err := winFiles(run)
	if err != nil {
		return nil, err
	}
	return files.ReadTail(filepath.Join(id, name), 128<<10)
}
func winWrite(run, name string, value any) error {
	files, id, e := winFiles(run)
	if e != nil {
		return e
	}
	return files.Write(filepath.Join(id, name), value)
}
func load(run string) (State, error) {
	raw, e := readRunFile(run, "state.json", 4<<20)
	if e != nil {
		return State{}, e
	}
	s, e := decodeState(raw, func() ([]byte, error) { return readRunFile(run, "run-spec.json", 2<<20) })
	if e != nil {
		return s, e
	}
	if s.Windows == nil || s.Windows.PublicRun != run || s.Windows.BootID == "" {
		return s, errors.New("administrator run identity mismatch")
	}
	if e := validateOwner(run, s.Manifest); e != nil {
		return s, e
	}
	return s, nil
}
func save(run string, s *State) error {
	s.Updated = time.Now()
	record, e := stateRecord(s)
	if e != nil {
		return e
	}
	if e := winWrite(run, "state.json", record); e != nil {
		return e
	}
	return securefile.Write(filepath.Join(run, "status.json"), publicStatus(*s, s.Updated))
}

func readRunFile(run, name string, limit int64) ([]byte, error) {
	files, id, err := winFiles(run)
	if err != nil {
		return nil, err
	}
	return files.Read(filepath.Join(id, name), limit)
}
func writeRunFile(run, name string, value any) error { return winWrite(run, name, value) }
func lockRunFile(run, name string, limit time.Duration) (func(), error) {
	files, id, err := winFiles(run)
	if err != nil {
		return nil, err
	}
	return files.Lock(filepath.Join(id, name), limit)
}
func update(run string, fn func(*State) error) error {
	files, id, e := winFiles(run)
	if e != nil {
		return e
	}
	unlock, e := files.Lock(filepath.Join(id, "state.lock"), 30*time.Second)
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
	if s.Windows != nil && !s.Windows.ValidationDeadline.IsZero() && !time.Now().Before(s.Windows.ValidationDeadline) {
		return errors.New("validation deadline reached")
	}
	if _, e := os.Lstat(filepath.Join(run, "STOP")); e == nil || !errors.Is(e, os.ErrNotExist) {
		return errors.New("stop requested or unreadable stop marker")
	}
	if s.Phase == "stopping" || s.Phase == "stopped" || s.Phase == "recovery_failed" {
		return errors.New("run is stopping")
	}
	return nil
}
func watcherReady(run string, s State) error {
	var ready platform.Identity
	if e := winRead(run, "watcher-ready.json", &ready); e != nil {
		return e
	}
	if !sameProcess(s.Watcher, ready) || !sameExecutable(ready.Executable, frozenSelf(run)) {
		return errors.New("watchdog readiness identity differs")
	}
	actual, e := platform.Process(ready.PID)
	if e != nil {
		return e
	}
	if !sameProcess(ready, actual) {
		return errors.New("ready watchdog is no longer alive")
	}
	return nil
}

func legacyPulse(run string) error {
	return update(run, func(s *State) error {
		if e := guard(run, s); e != nil {
			return e
		}
		if s.Watcher.PID > 0 {
			actual, e := platform.Process(s.Watcher.PID)
			if e != nil || !sameProcess(s.Watcher, actual) {
				return errors.New("independent watchdog disappeared")
			}
		}
		s.Heartbeat = time.Now()
		return nil
	})
}

func verifyPulseProcesses(s State) error {
	me, err := platform.Process(os.Getpid())
	if err != nil || !sameProcess(s.Runner, me) {
		return errors.New("unpublished coordinator cannot update heartbeat")
	}
	if s.Watcher.PID > 0 {
		actual, err := platform.Process(s.Watcher.PID)
		if err != nil || !sameProcess(s.Watcher, actual) {
			return errors.New("independent watchdog disappeared")
		}
	}
	return nil
}
func sameProcess(a, b platform.Identity) bool {
	return a.PID > 0 && a.PID == b.PID && a.Birth != "" && a.Birth == b.Birth && a.OwnerSID != "" && a.OwnerSID == b.OwnerSID && strings.EqualFold(a.Executable, b.Executable)
}
func alive(c Child) (bool, error) {
	if c.Native == nil {
		return false, errors.New("child native identity missing")
	}
	actual, e := platform.Process(c.Native.PID)
	return e == nil && sameProcess(*c.Native, actual), e
}
func stopChild(c Child) error {
	if c.Native == nil {
		return errors.New("child native identity missing")
	}
	actual, e := platform.Process(c.Native.PID)
	if e != nil {
		return e
	}
	if !sameProcess(*c.Native, actual) {
		return nil
	}
	if e = platform.StopIdentity(*c.Native); e != nil {
		return e
	}
	return awaitProcessExit(*c.Native, 10*time.Second)
}
func awaitProcessExit(id platform.Identity, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		actual, e := platform.Process(id.PID)
		if e != nil {
			return e
		}
		if !sameProcess(id, actual) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("owned process did not exit")
}
func networkManager(run string) (winstate.Manager, error) {
	files, id, e := winFiles(run)
	if e != nil {
		return winstate.Manager{}, e
	}
	return winstate.Manager{Store: winstate.NativeStorage{Files: files, RunID: id}, Native: winstate.NativeBackend{}}, nil
}
func readCore(run string, v any) error { return winRead(run, "core.json", v) }
func saveCore(run string, v any) error { return winWrite(run, "core.json", v) }

func cancelledStatus(run string) error {
	if _, e := ReadManifest(run); e != nil {
		return e
	}
	return securefile.Write(filepath.Join(run, "status.json"), Status{Phase: "stopped", Updated: time.Now(), Company: "unavailable", Personal: selector.Reject, RecoveryReason: "cancelled_before_network_changes", Experimental: true})
}

func sameExecutable(a, b string) bool { return strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) }
