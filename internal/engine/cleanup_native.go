//go:build darwin || windows

package engine

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"netlaunch/internal/securefile"
)

// The app holds the owning profile's launch.lock throughout this operation.
// No process termination, recovery or automatic elevation occurs here.
func CleanupRun(profile, run string, apply bool) (CleanupResult, error) {
	out := CleanupResult{Scope: "stopped_run_payloads", RecoveryRetained: true}
	if err := cleanupLocation(profile, run); err != nil {
		return out, err
	}
	if err := unreferencedRun(filepath.Join(profile, "current.json"), run); err != nil {
		return out, err
	}
	unlock, err := cleanupGlobalLock(run)
	if err != nil {
		return out, err
	}
	defer unlock()
	// An absent or unreadable privileged state is not proof of recovery.
	if _, err := load(run); err != nil {
		return out, err
	}
	for _, name := range []string{"recovery.lock", "state.lock", "heartbeat.lock"} {
		unlock, err := lockRunFile(run, name, time.Second)
		if err != nil {
			return out, err
		}
		defer unlock()
	}
	if err := cleanupEligible(run); err != nil {
		return out, err
	}
	var trees []*cleanupTree
	defer func() {
		for _, t := range trees {
			t.root.Close()
		}
	}()
	for _, path := range []string{private(run), run} {
		tree, err := planCleanupTree(path)
		if err != nil {
			return out, err
		}
		trees = append(trees, tree)
		out.Files += tree.files
		out.Bytes += tree.bytes
	}
	if apply {
		if err := cleanupEligible(run); err != nil {
			return out, err
		}
		for _, tree := range trees {
			if err := tree.apply(); err != nil {
				return out, errors.New("payload cleanup incomplete; recovery evidence retained; retry cleanup")
			}
		}
		out.Applied = true
	}
	return out, nil
}

func unreferencedRun(path, run string) error {
	b, err := securefile.Read(path, 4096, true)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var ref struct {
		Run string `json:"run"`
	}
	if json.Unmarshal(b, &ref) != nil || ref.Run == "" {
		return errors.New("invalid current run reference")
	}
	if sameCleanupPath(ref.Run, run) {
		return errors.New("current run is retained; cleanup only historical runs")
	}
	return nil
}

func cleanupEligible(run string) error {
	s, err := load(run)
	if err != nil {
		return err
	}
	if s.Phase != "stopped" || s.Error != "" {
		return errors.New("privileged recovery is not complete")
	}
	if err := validateOwner(run, s.Manifest); err != nil {
		return err
	}
	if _, err := securefile.Read(filepath.Join(run, "STOP"), 4096, true); err != nil {
		return errors.New("cleanup requires the durable stop marker")
	}
	for _, pid := range []int{s.Runner.PID, s.Watcher.PID} {
		if err := cleanupProcessGone(pid); err != nil {
			return err
		}
	}
	for _, child := range s.Children {
		if err := cleanupProcessGone(child.PID); err != nil {
			return err
		}
		if child.Native != nil {
			if err := cleanupProcessGone(child.Native.PID); err != nil {
				return err
			}
		}
	}
	return cleanupRecovered(run, s)
}
