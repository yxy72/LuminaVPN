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
	s.PersonalFallbackUntil, s.DarwinAutoFallbackUntil = nil, nil
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

func requireDarwinFallbackWake(wake string) error {
	if actual, err := platform.WakeEpoch(); err != nil || actual != wake {
		return errFallbackLeaseStateChanged
	}
	return nil
}

func setDarwinFallbackLease(ctx context.Context, run, wake string, operation fallbackLeaseOperation, expiresAt time.Time) (time.Time, error) {
	return setFallbackLease(ctx, operation, expiresAt, func(work context.Context, method string, in, out any) error {
		if method == "PUT" {
			// The core clock was read before this check. A grant sent past a
			// later wake can only use the core deadline from that observation.
			if err := requireDarwinFallbackWake(wake); err != nil {
				return err
			}
		}
		return apiContext(work, run, method, personalFallbackLeasePath, in, out)
	})
}

func publishDarwinAutoFallback(ctx context.Context, s *State, direct bool, until time.Time, authorize func(State) error, selectGroup func(context.Context, string, string) error, openLease func(context.Context, time.Time) (time.Time, error)) error {
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
	if err := selectGroup(ctx, "PHYSICAL", "PHYSICAL-BOUND"); err != nil {
		return err
	}
	var readback time.Time
	if direct {
		if err := check(); err != nil {
			return err
		}
		cutoff, err := openLease(ctx, until)
		if err != nil {
			return err
		}
		if cutoff.After(until) || !time.Now().Before(cutoff) {
			return errors.New("macOS automatic fallback did not confirm a current lease")
		}
		readback = cutoff
	}
	if err := check(); err != nil {
		return err
	}
	s.DarwinAutoFallbackPending, s.PersonalFallback = false, direct
	s.Personal = selector.Reject
	if direct {
		s.Personal = "PHYSICAL"
		s.PersonalFallbackUntil = &readback
	}
	return nil
}

func applyDarwinAutoFallback(ctx context.Context, run string, before State, company *companyRuntime, previous *personalVerification, nodes []policy.Node, secret, wake string, direct bool, deadline func(State) time.Time) (*personalVerification, time.Time, error) {
	allows := func(s State) bool {
		return !darwinManualReadbackPending(run, s) && deadline(s).After(time.Now().Add(time.Second))
	}
	// Revoke an expired or superseded direct route immediately. In particular,
	// configuration preflight must not prolong the old authorization.
	if !direct {
		if err := closeDarwinFallbackPaths(ctx, run); err != nil {
			return nil, time.Time{}, err
		}
	}
	if direct && !allows(before) {
		return nil, time.Time{}, errDarwinFallbackDeferred
	}
	manifest := before.Manifest
	effective := currentIntent(before)
	manifest.Channels = &effective
	// Keeping the explicit node adapters lets the authenticated controller
	// continue independent delay checks without a candidate listener or a
	// matching public rule pointing at those adapters during fallback.
	config, verification, err := stageDarwinPersonalConfig(ctx, run, manifest, nodes, company, secret, direct)
	if err != nil {
		if direct {
			return nil, time.Time{}, errDarwinFallbackDeferred
		}
		return nil, time.Time{}, err
	}
	if err := verifyDarwinPersonalResolverOwnership(before); err != nil {
		if direct {
			return nil, time.Time{}, errDarwinFallbackDeferred
		}
		return nil, time.Time{}, err
	}
	if err := update(run, func(s *State) error {
		if err := checkDarwinCompanyOwner(run, *s); err != nil {
			return err
		}
		return beginDarwinAutoFallback(s, before, direct, allows)
	}); err != nil {
		if !direct && errors.Is(err, errDarwinFallbackDeferred) {
			return nil, time.Time{}, errors.New("could not restore macOS proxy mode after closing direct fallback")
		}
		return nil, time.Time{}, err
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
	failClosed := func(err error) (*personalVerification, time.Time, error) {
		if fallbackAttempted {
			// The core may have granted the lease before readback failed.
			return nil, time.Time{}, errors.Join(err, closeDarwinFallbackPaths(ctx, run))
		}
		return nil, time.Time{}, errors.Join(err, closeDarwinBasePaths(ctx, run))
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
		if err := requireDarwinFallbackWake(wake); err != nil {
			return err
		}
		return authorize(s)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var proofUntil time.Time
	if err := update(run, func(s *State) error {
		if direct {
			proofUntil = darwinFallbackCutoff(*s, deadline(*s))
		}
		return publishDarwinAutoFallback(ctx, s, direct, proofUntil, authorizePublication, func(work context.Context, group, target string) error {
			return selectCoreGroupContext(work, run, group, target)
		}, func(work context.Context, cutoff time.Time) (time.Time, error) {
			fallbackAttempted = true
			return setDarwinFallbackLease(work, run, wake, openFallbackLease, cutoff)
		})
	}); err != nil {
		return failClosed(err)
	}
	return verification, proofUntil, nil
}

// The heartbeat also attempts to revoke the selector and close tracked
// fallback connections when the owning loop is busy. The fallback marker
// remains until the owning loop finishes restoring the regular resolver.
func darwinFallbackExpired(s State, now time.Time) bool {
	until := fallbackUntil(s)
	return s.PersonalFallback && s.Personal == "PHYSICAL" &&
		(until == nil || !now.Before(*until))
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
		if slices.Equal(connection.Chains, []string{"REJECT", "PERSONAL"}) {
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

func renewDarwinFallback(ctx context.Context, run, wake string, before State, previousProof time.Time, deadline func(State) time.Time) (time.Time, error) {
	until := darwinFallbackCutoff(before, deadline(before))
	if !until.After(previousProof) {
		return previousProof, nil
	}
	published := previousProof
	err := update(run, func(s *State) error {
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
		if until.After(previousProof) {
			readback, err := setDarwinFallbackLease(ctx, run, wake, renewFallbackLease, until)
			if err != nil {
				return err
			}
			if err := requireDarwinFallbackWake(wake); err != nil {
				return err
			}
			s.PersonalFallbackUntil = &readback
			published = until
		}
		return nil
	})
	return published, err
}
