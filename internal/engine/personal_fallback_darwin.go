//go:build darwin

package engine

import (
	"context"
	"errors"
	"slices"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/selector"
)

var errDarwinFallbackDeferred = errors.New("macOS automatic personal fallback has no current authority")

func darwinManualChangePending(s State) bool {
	return s.DarwinCompany != nil && s.DarwinCompany.Pending || s.DarwinPersonal != nil && s.DarwinPersonal.Pending
}

func darwinManualReadbackPending(run string, s State) bool {
	return s.DarwinPersonal != nil && darwinPersonalPermit(run, s.DarwinPersonal.RequestID) ||
		s.DarwinCompany != nil && s.DarwinCompany.DesktopBound && darwinCompanyPermit(run, s.DarwinCompany.RequestID)
}

func sameDarwinFallbackRun(current, before State) bool {
	intent := currentIntent(current)
	return current.TakeoverActive && current.Manifest.Mode != "" && intent.Personal &&
		current.RunSpecDigest == before.RunSpecDigest && current.Runner == before.Runner &&
		current.Manifest.Network == before.Manifest.Network && current.Manifest.Binding == before.Manifest.Binding &&
		current.ChannelGeneration == before.ChannelGeneration && current.AppliedGeneration == current.ChannelGeneration &&
		current.AppliedChannels != nil && *current.AppliedChannels == intent && intent == currentIntent(before)
}

func beginDarwinAutoFallback(s *State, before State, direct bool, allows func(State) bool) error {
	if !sameDarwinFallbackRun(*s, before) || s.DarwinAutoFallbackPending || s.PersonalFallback == direct ||
		direct && (darwinManualChangePending(*s) || !allows(*s)) {
		return errDarwinFallbackDeferred
	}
	s.DarwinAutoFallbackPending = true
	s.PersonalFallback = false
	s.DarwinAutoFallbackUntil = nil
	s.Personal, s.Phase = selector.Reject, "reconnecting"
	s.Channels = nil
	return nil
}

func darwinFallbackCutoff(s State, proofDeadline time.Time) time.Time {
	runDeadline := darwinRunDeadline(s.Manifest)
	if !proofDeadline.IsZero() && !runDeadline.IsZero() && runDeadline.Before(proofDeadline) {
		return runDeadline
	}
	return proofDeadline
}

func publishDarwinAutoFallback(ctx context.Context, s *State, direct bool, until time.Time, authorize func(State) error, selectGroup func(context.Context, string, string) error) error {
	if direct {
		if until.IsZero() {
			return errDarwinFallbackDeferred
		}
		until = darwinFallbackCutoff(*s, until)
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, until)
		defer cancel()
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if direct && !time.Now().Before(until) {
			return context.DeadlineExceeded
		}
		return authorize(*s)
	}
	if err := check(); err != nil {
		return err
	}
	if err := openDesktopConfig(func(group, target string) error {
		if err := check(); err != nil {
			return err
		}
		return selectGroup(ctx, group, target)
	}, direct); err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	s.DarwinAutoFallbackPending, s.PersonalFallback = false, direct
	s.Personal = selector.Reject
	if direct {
		s.Personal = "PHYSICAL"
		s.DarwinAutoFallbackUntil = &until
	}
	return nil
}

func applyDarwinAutoFallback(ctx context.Context, run string, before State, company *companyRuntime, previous *personalVerification, nodes []policy.Node, secret, wake string, direct bool, deadline func(State) time.Time) (*personalVerification, error) {
	allows := func(s State) bool {
		return !darwinManualReadbackPending(run, s) && deadline(s).After(time.Now().Add(time.Second))
	}
	// Revoke an expired or superseded direct route immediately. In particular,
	// configuration preflight must not prolong the old authorization.
	if !direct {
		if err := closeDarwinFallbackPaths(ctx, run); err != nil {
			return nil, err
		}
	}
	if direct && !allows(before) {
		return nil, errDarwinFallbackDeferred
	}
	manifest := before.Manifest
	effective := currentIntent(before)
	effective.Personal = !direct
	manifest.Channels = &effective
	// Keeping the explicit node adapters lets the authenticated controller
	// continue independent delay checks without a candidate listener or a
	// matching public rule pointing at those adapters during fallback.
	config, verification, err := stageDarwinPersonalConfig(ctx, run, manifest, nodes, company, secret, direct)
	if err != nil {
		if direct {
			return nil, errDarwinFallbackDeferred
		}
		return nil, err
	}
	if err := verifyDarwinPersonalResolverOwnership(before); err != nil {
		if direct {
			return nil, errDarwinFallbackDeferred
		}
		return nil, err
	}
	if err := update(run, func(s *State) error {
		if err := checkDarwinCompanyOwner(run, *s); err != nil {
			return err
		}
		return beginDarwinAutoFallback(s, before, direct, allows)
	}); err != nil {
		if !direct && errors.Is(err, errDarwinFallbackDeferred) {
			return nil, errors.New("could not restore macOS proxy mode after closing direct fallback")
		}
		return nil, err
	}
	authorize := func(s State) error {
		if err := checkDarwinCompanyOwner(run, s); err != nil {
			return err
		}
		if !sameDarwinFallbackRun(s, before) || !s.DarwinAutoFallbackPending ||
			direct && (darwinManualChangePending(s) || !allows(s)) {
			return errors.New("macOS fallback authorization changed during resolver transition")
		}
		return nil
	}
	fallbackAttempted := false
	failClosed := func(err error) (*personalVerification, error) {
		if fallbackAttempted {
			// The controller may have accepted a selector write before readback failed.
			return nil, errors.Join(err, closeDarwinFallbackPaths(ctx, run))
		}
		return nil, errors.Join(err, closeDarwinBasePaths(ctx, run))
	}
	if err := closeDarwinVerification(run, previous); err != nil {
		return failClosed(err)
	}
	if err := prepareDarwinPersonalReload(ctx, run, before, config, authorize); err != nil {
		return failClosed(err)
	}
	if err := verifyDarwinPersonalResolverOwnership(before); err != nil {
		return failClosed(err)
	}
	authorizePublication := func(s State) error {
		if actual, err := platform.WakeEpoch(); err != nil || actual != wake {
			return errors.New("macOS wake generation changed during fallback")
		}
		return authorize(s)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := update(run, func(s *State) error {
		var until time.Time
		if direct {
			until = deadline(*s)
		}
		return publishDarwinAutoFallback(ctx, s, direct, until, authorizePublication, func(work context.Context, group, target string) error {
			fallbackAttempted = fallbackAttempted || group == "PERSONAL" && target == "PHYSICAL"
			return selectCoreGroupContext(work, run, group, target)
		})
	}); err != nil {
		return failClosed(err)
	}
	return verification, nil
}

// The heartbeat also attempts to revoke the selector and close tracked
// fallback connections when the owning loop is busy. The fallback marker
// remains until the owning loop finishes restoring the regular resolver.
func darwinFallbackExpired(s State, now time.Time) bool {
	return s.PersonalFallback && s.Personal == "PHYSICAL" &&
		(s.DarwinAutoFallbackUntil == nil || !now.Before(*s.DarwinAutoFallbackUntil))
}

func fenceExpiredDarwinFallback(ctx context.Context, run string) error {
	now := time.Now()
	s, err := load(run)
	if err != nil || !darwinFallbackExpired(s, now.Add(time.Second)) {
		return err
	}
	return update(run, func(current *State) error {
		if !darwinFallbackExpired(*current, time.Now().Add(time.Second)) {
			return nil
		}
		// Tightening this run's gate is still permitted after STOP or run expiry.
		if err := requireActiveDarwinOwner(run, *current); err != nil {
			return err
		}
		// Time waiting for state.lock must not prevent the native REJECT attempt.
		work, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if err := selectPersonalContext(work, run, selector.Reject); err != nil {
			return err
		}
		request := func(method, path string, payload, out any) error {
			return apiContext(work, run, method, path, payload, out)
		}
		if err := drainDarwinFallbackConnections(request); err != nil {
			return err
		}
		current.Personal, current.Channels = selector.Reject, nil
		return nil
	})
}

func closeDarwinFallbackPaths(ctx context.Context, run string) error {
	gateErr := closeDarwinBasePaths(ctx, run)
	work, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	drainErr := drainDarwinFallbackConnections(func(method, path string, payload, out any) error {
		return apiContext(work, run, method, path, payload, out)
	})
	return errors.Join(gateErr, drainErr)
}

func drainDarwinFallbackConnections(request func(method, path string, payload, out any) error) error {
	connections, err := desktopConnections(request)
	if err != nil {
		return err
	}
	for _, connection := range connections {
		if !slices.Contains(connection.Chains, "PERSONAL") {
			continue
		}
		if !slices.Contains(connection.Chains, "PHYSICAL") || slices.Contains(connection.Chains, "CORP") || slices.Contains(connection.Chains, "CORP-BOUND") {
			return errors.New("unexpected personal connection during macOS fallback expiry")
		}
		if err := closeDesktopConnection(connection.ID, request); err != nil {
			return err
		}
	}
	return nil
}

func renewDarwinFallback(ctx context.Context, run string, before State, deadline func(State) time.Time) error {
	until := darwinFallbackCutoff(before, deadline(before))
	if before.DarwinAutoFallbackUntil != nil && !until.After(*before.DarwinAutoFallbackUntil) {
		return nil
	}
	return update(run, func(s *State) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := guard(run, s); err != nil {
			return err
		}
		if !sameDarwinFallbackRun(*s, before) || !s.PersonalFallback || s.Personal != "PHYSICAL" ||
			darwinManualChangePending(*s) || darwinFallbackExpired(*s, time.Now()) {
			return nil
		}
		until := darwinFallbackCutoff(*s, deadline(*s))
		if until.After(time.Now()) && (s.DarwinAutoFallbackUntil == nil || until.After(*s.DarwinAutoFallbackUntil)) {
			s.DarwinAutoFallbackUntil = &until
		}
		return nil
	})
}
