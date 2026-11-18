package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"netlaunch/internal/engine"
	"netlaunch/internal/platform"
	"netlaunch/internal/securefile"
)

// RunStop binds stop and recovery operations to one already published run.
// It never follows a newer current.json after binding. The caller closes it
// after the last operation.
type RunStop struct {
	path     string
	dir      *os.Root
	identity os.FileInfo
}

// BindCurrentRunStop binds the current run directly under the caller's profile.
// Desktop callers supply the validated local profile, not a renderer run path.
func BindCurrentRunStop(ctx context.Context, profile string) (*RunStop, error) {
	if !platform.Supported() {
		return nil, errors.New("native lifecycle unavailable on this platform")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	profile, err := filepath.Abs(profile)
	if err != nil {
		return nil, err
	}
	if err := securefile.CheckDir(profile); err != nil {
		return nil, err
	}
	stop, err := bindRunStop(ctx, options{profile: profile})
	if err != nil {
		return nil, err
	}
	if !engine.MacServiceProfileRun(profile, stop.path) {
		runs := filepath.Join(profile, "runs")
		if err := securefile.CheckDir(runs); err != nil {
			stop.Close()
			return nil, err
		}
		runs, err = filepath.EvalSymlinks(runs)
		if err != nil || filepath.Dir(stop.path) != runs {
			stop.Close()
			return nil, errors.New("current run is outside the selected profile")
		}
	}
	manifest, err := engine.ReadManifest(stop.path)
	if err != nil {
		stop.Close()
		return nil, err
	}
	owner, sid, err := engine.OwnerIdentity()
	if err != nil || owner != manifest.Owner || sid != manifest.OwnerSID {
		stop.Close()
		return nil, errors.New("current run belongs to another user")
	}
	if err := stop.check(ctx); err != nil {
		stop.Close()
		return nil, err
	}
	return stop, nil
}

func bindRunStop(ctx context.Context, o options) (*RunStop, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	run, err := currentRun(o)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(run)
	if err != nil {
		return nil, err
	}
	dir, err := os.OpenRoot(run)
	if err != nil {
		return nil, err
	}
	pinned, err := dir.Stat(".")
	if err != nil || !os.SameFile(info, pinned) {
		dir.Close()
		return nil, errors.New("run directory was replaced while binding")
	}
	stop := &RunStop{path: run, dir: dir, identity: pinned}
	if err := stop.check(ctx); err != nil {
		stop.Close()
		return nil, err
	}
	return stop, nil
}

func (r *RunStop) Close() error { return r.dir.Close() }

func (r *RunStop) Matches(run string, identity os.FileInfo) bool {
	return identity != nil && r.path == run && os.SameFile(r.identity, identity)
}

func (r *RunStop) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := engine.ValidateRun(r.path); err != nil {
		return err
	}
	info, err := os.Lstat(r.path)
	if err != nil || !os.SameFile(r.identity, info) {
		return errors.New("bound run directory was replaced")
	}
	return nil
}

// Request creates the run's ordinary STOP marker. It does not wait or ask for
// administrator authorization. Cancellation never removes a committed marker.
func (r *RunStop) Request(ctx context.Context) error {
	if err := r.check(ctx); err != nil {
		return err
	}
	if runtime.GOOS != "darwin" {
		// The Windows CLI still uses the existing protected file writer.
		return securefile.Bytes(filepath.Join(r.path, "STOP"), nil)
	}
	// An empty, exclusive create is publication. Use the pinned directory so
	// a concurrent rename cannot redirect this write to a different run.
	f, err := r.dir.OpenFile("STOP", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		info, err := r.dir.Lstat("STOP")
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("invalid existing STOP marker")
		}
		return r.check(ctx)
	}
	if err != nil {
		return err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	if d, err := r.dir.Open("."); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return r.check(ctx)
}

// RunRecoveryReport is the user-readable snapshot. A stopped report alone is
// not privileged proof of current ownership or network restoration.
type RunRecoveryReport struct {
	SavedPhase string
	SavedAt    time.Time
}

func (r *RunStop) Observe(ctx context.Context) (RunRecoveryReport, error) {
	if err := r.check(ctx); err != nil {
		return RunRecoveryReport{}, err
	}
	status, readErr := statusFor(r.path)
	if err := r.check(ctx); err != nil {
		return RunRecoveryReport{}, err
	}
	if readErr != nil {
		return RunRecoveryReport{}, nil
	}
	return RunRecoveryReport{SavedPhase: status.Phase, SavedAt: status.Updated}, nil
}

// WaitForStoppedReport observes recovery by the independent watcher. The
// caller sets its wait deadline. It never writes STOP or escalates privileges.
func (r *RunStop) WaitForStoppedReport(ctx context.Context) error {
	return r.waitForStoppedReport(ctx, time.Second)
}

func (r *RunStop) waitForStoppedReport(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		report, err := r.Observe(ctx)
		if err != nil || report.SavedPhase == "stopped" {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Recover explicitly delegates to the existing native recovery entry. Once
// submitted, the OS may continue recovery even if the caller is cancelled.
func (r *RunStop) Recover(ctx context.Context) error {
	return r.recover(ctx, func(run string) error { return engine.LaunchContext(ctx, "recover", run) })
}

// RecoverVerified requests native recovery and requires an administrator-owned
// receipt for this run even if the user-readable status already says stopped.
func (r *RunStop) RecoverVerified(ctx context.Context) error {
	if runtime.GOOS != "darwin" {
		return errors.New("native verified recovery is unavailable on this platform")
	}
	if err := r.Request(ctx); err != nil {
		return err
	}
	if err := r.check(ctx); err != nil {
		return err
	}
	if err := engine.LaunchContext(ctx, "recover-verified", r.path); err != nil {
		return err
	}
	return r.check(ctx)
}

func (r *RunStop) recover(ctx context.Context, launch func(string) error) error {
	if err := r.Request(ctx); err != nil {
		return err
	}
	if err := r.check(ctx); err != nil {
		return err
	}
	if err := launch(r.path); err != nil {
		return err
	}
	status, err := r.Observe(ctx)
	if err != nil {
		return err
	}
	if status.SavedPhase != "stopped" {
		return errors.New("recovery is incomplete; preserve this run directory and retry down")
	}
	return nil
}
