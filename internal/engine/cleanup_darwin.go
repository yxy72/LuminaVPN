//go:build darwin

package engine

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"netlaunch/internal/securefile"
)

func sameCleanupPath(a, b string) bool { return filepath.Clean(a) == filepath.Clean(b) }

func cleanupGlobalLock(run string) (func(), error) {
	if err := validateRoot(run); err != nil {
		return nil, err
	}
	return securefile.Lock(filepath.Join(filepath.Dir(private(run)), "active.lock"), time.Second)
}

func cleanupProcessGone(pid int) error {
	if pid == 0 {
		return nil
	}
	if pid < 2 {
		return errors.New("invalid recorded process id")
	}
	// ps failures must not be interpreted as proof that a process is gone.
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return errors.New("recorded process id is still in use or cannot be checked")
}

func cleanupRecovered(_ string, s State) error {
	if os.Geteuid() != 0 {
		return errors.New("administrator terminal required")
	}
	for _, r := range s.Routes {
		if r.State != "removed" {
			return errors.New("route recovery is incomplete")
		}
	}
	// DNS readback precedes the privileged stopped snapshot. Do not compare
	// current network DNS to an old run: a later run may legitimately change it.
	return nil
}
