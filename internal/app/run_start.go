package app

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"netlaunch/internal/engine"
	"netlaunch/internal/securefile"
)

const startupReadinessWindow = 150 * time.Second

// StartMacNetwork uses the native macOS controller with the profile and
// runtime selected by the desktop host. The caller controls the operation
// lifetime independently of the bridge's per-request deadline.
func StartMacNetwork(ctx context.Context, profile, bundle string, validation time.Duration) error {
	if runtime.GOOS != "darwin" || os.Geteuid() == 0 {
		return errors.New("macOS desktop startup requires the ordinary user")
	}
	if !filepath.IsAbs(profile) || filepath.Clean(profile) != profile ||
		!filepath.IsAbs(bundle) || filepath.Clean(bundle) != bundle {
		return errors.New("local desktop profile or runtime is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := securefile.CheckDir(profile); err != nil {
		return err
	}
	o := options{profile: profile, runtime: bundle, validationTimeout: validation}
	if err := validateLaunchOptions(&o, "up"); err != nil {
		return err
	}
	c := CLI{Out: io.Discard, Err: io.Discard}
	return c.startProfileContext(ctx, o)
}

// A launch response can fail after the native system has accepted the request.
// Stop is committed to the original run before returning from unsettled startup.
func launchPreparedRun(ctx context.Context, stop *RunStop, launch func(context.Context, string, string) error, status func(string) (engine.Status, error), timeout, interval time.Duration) (s engine.Status, resultErr error) {
	finished := false
	defer func() {
		if finished || resultErr == nil {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		if err := stop.Request(cleanup); err != nil {
			resultErr = errors.Join(resultErr, errors.New("the prepared run could not be stopped; use its recovery entry"))
		}
	}()
	if err := stop.check(ctx); err != nil {
		return s, err
	}
	if err := launch(ctx, "serve", stop.path); err != nil {
		return s, err
	}

	wait, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := wait.Err(); err != nil {
			if ctx.Err() != nil {
				return s, ctx.Err()
			}
			return s, errors.New("startup readiness deadline exceeded; a stop was requested")
		}
		if err := stop.check(wait); err != nil {
			return s, err
		}
		observed, err := status(stop.path)
		if err == nil {
			if err := stop.check(wait); err != nil {
				return s, err
			}
			switch observed.Phase {
			case "ready":
				finished = true
				return observed, nil
			case "stopped":
				finished = true
				if engine.NeedsAuthentication(observed) {
					return s, errors.New("VPN authentication was rejected or expired; run auth, then up")
				}
				return s, errors.New("startup did not complete; inspect status and use the recovery entry")
			case "recovery_failed":
				return s, errors.New("startup recovery did not complete; inspect status and use the recovery entry")
			}
		}
		select {
		case <-wait.Done():
		case <-ticker.C:
		}
	}
}
