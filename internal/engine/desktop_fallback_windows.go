//go:build windows

package engine

import (
	"context"
	"time"

	"netlaunch/internal/personalroute"
	"netlaunch/internal/selector"
	"netlaunch/internal/winnet"
)

// requested is the evidence deadline already attempted, not the earlier cutoff
// reported by the core. Keep it after withdrawal to avoid reusing old proof.
type desktopFallbackLease struct {
	requested time.Time
	until     time.Time
}

func desktopFallbackDeadline(decision personalroute.Decision, validation, now time.Time) time.Time {
	if !decision.DirectAllowed || decision.Reason != personalroute.ReasonAllFailed {
		return time.Time{}
	}
	deadline := decision.ExpiresAt
	if !validation.IsZero() && validation.Before(deadline) {
		deadline = validation
	}
	if !now.Before(deadline) {
		return time.Time{}
	}
	return deadline
}

func (l desktopFallbackLease) shouldWithdraw(deadline, now time.Time) bool {
	return !l.until.IsZero() && (!now.Before(l.until) || deadline.Before(l.requested))
}

func (l *desktopFallbackLease) next(deadline time.Time) (fallbackLeaseOperation, bool) {
	if !deadline.After(l.requested) {
		return "", false
	}
	l.requested = deadline
	if !l.until.IsZero() {
		return renewFallbackLease, true
	}
	return openFallbackLease, true
}

func desktopFallbackCoreActive(ctx context.Context, run string) bool {
	work, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var state fallbackLeaseState
	return apiContext(work, run, "GET", personalFallbackLeasePath, nil, &state) == nil &&
		state.Active && state.Revision != "" && len(state.Revision) <= 128 &&
		state.NowMS >= 0 && state.DeadlineMS > state.NowMS
}

func sameDesktopPhysical(a, b winnet.Physical) bool {
	return winnet.SameAdapter(a.Adapter, b.Adapter) && a.Address == b.Address && a.Gateway == b.Gateway
}

func sameDesktopFallbackScope(a, b State) bool {
	return a.Windows != nil && b.Windows != nil && a.Windows.BootID == b.Windows.BootID &&
		a.Windows.PublicRun == b.Windows.PublicRun && a.Windows.Epoch == b.Windows.Epoch &&
		sameDesktopPhysical(a.Windows.Physical, b.Windows.Physical) &&
		a.Windows.ValidationDeadline.Equal(b.Windows.ValidationDeadline) &&
		a.RunSpecDigest == b.RunSpecDigest && sameProcess(a.Runner, b.Runner) &&
		a.ChannelGeneration == b.ChannelGeneration && b.ChannelGeneration == b.AppliedGeneration &&
		b.TakeoverActive && b.AppliedChannels != nil && b.AppliedChannels.Personal &&
		currentIntent(a) == *b.AppliedChannels && currentIntent(b) == *b.AppliedChannels
}

func confirmDesktopFallbackScope(run string, proof, current *State) error {
	if err := guard(run, current); err != nil {
		return err
	}
	if !sameDesktopFallbackScope(*proof, *current) {
		return errFallbackLeaseStateChanged
	}
	physical, err := winnet.Discover()
	epoch, awake := windowsPower.Epoch()
	if err != nil || !awake || epoch != current.Windows.Epoch || !sameDesktopPhysical(physical, current.Windows.Physical) {
		return errFallbackLeaseStateChanged
	}
	return nil
}

func applyDesktopFallbackLease(ctx context.Context, run string, proof State, op fallbackLeaseOperation, deadline time.Time) (time.Time, error) {
	work, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var cutoff time.Time
	err := update(run, func(s *State) error {
		if err := confirmDesktopFallbackScope(run, &proof, s); err != nil {
			return err
		}
		if op == renewFallbackLease {
			if !activePersonalFallback(*s, time.Now()) {
				return errFallbackLeaseStateChanged
			}
		} else if s.PersonalFallback || s.PersonalFallbackUntil != nil {
			return errFallbackLeaseStateChanged
		}
		var err error
		cutoff, err = setPersonalFallbackLease(work, run, op, deadline)
		if err != nil {
			return err
		}
		if err := confirmDesktopFallbackScope(run, &proof, s); err != nil {
			return err
		}
		if !time.Now().Before(cutoff) || work.Err() != nil {
			return context.DeadlineExceeded
		}
		s.Personal, s.PersonalFallback = "PHYSICAL", true
		s.PersonalFallbackUntil = &cutoff
		return nil
	})
	// The coordinator closes and verifies the gate before changing the
	// configuration if the controller result or its journal write is uncertain.
	return cutoff, err
}

func closeDesktopFallbackGate(run string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return selectPersonalContext(ctx, run, selector.Reject)
}

func clearDesktopFallback(s *State) {
	s.Personal = selector.Reject
	s.PersonalFallback = false
	s.PersonalFallbackUntil = nil
	delete(s.Channels, "personal")
}

func revokeDesktopFallback(run string) error {
	if err := closeDesktopFallbackGate(run); err != nil {
		return err
	}
	return update(run, func(s *State) error {
		clearDesktopFallback(s)
		return nil
	})
}
