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
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
)

const startupReadinessWindow = 150 * time.Second

// Typed desktop callers can direct the ordinary user to the authentication action.
var ErrMacAuthenticationRequired = errors.New("macOS company VPN authentication is required")

// StartMacNetworkWithIntent applies the intent to a single native run. Company
// authentication must already be present when the company channel is enabled.
func StartMacNetworkWithIntent(ctx context.Context, profile, bundle string, validation time.Duration, intent policy.ChannelIntent) error {
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
	o := options{profile: profile, runtime: bundle, validationTimeout: validation, channels: &intent, mode: engine.Daily}
	if validation != 0 {
		o.mode = engine.Validation
	}
	if err := validateLaunchOptions(&o, "up"); err != nil {
		return err
	}
	c := CLI{Out: io.Discard, Err: io.Discard}
	return c.startProfileContext(ctx, o)
}

func macStartupReportAccepted(s engine.Status, expected *policy.ChannelIntent, now time.Time) bool {
	if expected == nil {
		return s.Phase == "ready"
	}
	if (s.Phase != "managed" && s.Phase != "ready" && s.Phase != "degraded") ||
		s.Lifecycle != "running" || !s.TakeoverActive || s.ChannelGeneration == 0 ||
		s.AppliedGeneration != s.ChannelGeneration || s.DesiredChannels == nil || s.AppliedChannels == nil ||
		*s.DesiredChannels != *expected || *s.AppliedChannels != *expected {
		return false
	}
	s = engine.RefreshStatus(s, now)
	verified := func(channel string) bool {
		h := s.Channels[channel]
		return h.State == "ready" && h.ProbeScope == "system_tun" && h.PathState == "verified"
	}
	return verified("direct") && (!expected.Company || verified("company"))
}

// A launch response can fail after the native system has accepted the request.
// Stop is committed to the original run before returning from unsettled startup.
func launchPreparedRun(ctx context.Context, stop *RunStop, launch func(context.Context, string, string) error, status func(string) (engine.Status, error), timeout, interval time.Duration, expected *policy.ChannelIntent) (s engine.Status, resultErr error) {
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
			if macStartupReportAccepted(observed, expected, time.Now()) {
				finished = true
				return observed, nil
			}
			switch observed.Phase {
			case "stopped":
				finished = true
				if engine.NeedsAuthentication(observed) {
					e := errors.New("VPN authentication was rejected or expired; run auth, then up")
					if runtime.GOOS == "darwin" && observed.DesiredChannels != nil {
						e = errors.Join(e, ErrMacAuthenticationRequired)
					}
					return s, e
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
