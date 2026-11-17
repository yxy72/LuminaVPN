//go:build darwin || windows

package engine

import (
	"context"
	"errors"
	"time"

	"netlaunch/internal/policy"
	"netlaunch/internal/selector"
)

const (
	minimumPersonalVerificationSlices = 3
	personalVerificationParallelLimit = 16
)

func (s *probeSchedule) bindPersonalVerification(scope probeScope, probes []policy.Probe) {
	// Fit more targets into the existing verification window. Keep enough
	// result slots for previous workers to drain even after a smaller rebind.
	workers := (len(probes) + minimumPersonalVerificationSlices - 1) / minimumPersonalVerificationSlices
	s.parallel = max(defaultProbeParallelism, min(workers, cap(s.done)))
	s.bind(scope, probes)
}

func (s *probeSchedule) personalVerificationSliceLimit() int {
	// Allow one complete pass even when the configured targets exceed the
	// three-slice retry budget for small lists. The caller's deadline still
	// bounds wall-clock time, and each slice retains its worker limit.
	coverage := (len(s.probes) + s.parallel - 1) / s.parallel
	return max(minimumPersonalVerificationSlices, coverage)
}

// Only the coordinator changes either group. The candidate may advance over
// several ticks without changing the previously verified live selection.
type personalVerification struct {
	ingress   candidateIngress
	candidate *probeSchedule
	mixed     *probeSchedule
	policy    *selector.Policy
	node      string
	scope     probeScope
	previous  string
	slices    int
	deadline  time.Time
}

func newPersonalVerification(m Manifest) (*personalVerification, error) {
	ingress, err := newCandidateIngress(m)
	if err != nil {
		return nil, err
	}
	return &personalVerification{
		ingress:   ingress,
		candidate: newProbeScheduleWithCapacity(personalVerificationParallelLimit),
		mixed:     newProbeScheduleWithCapacity(personalVerificationParallelLimit),
	}, nil
}

func personalTargets(c policy.Config) []policy.Probe {
	var probes []policy.Probe
	for _, p := range c.Probes {
		if p.Channel == "personal" {
			probes = append(probes, p)
		}
	}
	return probes
}

func (v *personalVerification) pending() bool { return v.node != "" }

func (v *personalVerification) close(run string) error {
	if !v.pending() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := selectCoreGroupContext(ctx, run, candidateGroup, selector.Reject); err != nil {
		return err
	}
	v.node = ""
	v.candidate.reset()
	return nil
}

func (v *personalVerification) advance(ctx context.Context, run string, before State, p *selector.Policy, decide func(time.Time) (string, string)) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(err, v.close(run))
	}
	if err := guard(run, &before); err != nil {
		return errors.Join(err, v.close(run))
	}
	if v.pending() && (p != v.policy || scopeForProbes(before, v.node) != v.scope || before.Personal != v.previous) {
		if err := v.close(run); err != nil {
			return err
		}
	}
	probes := personalTargets(before.Manifest.Config)
	if !v.pending() {
		node, reason := decide(time.Now())
		if node == p.Current && before.Personal == node {
			return nil
		}
		if node == selector.Reject || (p.Current != selector.Reject && reason == "initial_or_failed_node") {
			if err := setVerifiedPersonal(ctx, run, before, selector.Reject, nil); err != nil {
				return err
			}
			p.Commit(selector.Reject, time.Now())
			before.Personal = selector.Reject
		}
		if node == selector.Reject {
			return nil
		}
		v.node, v.policy, v.previous = node, p, before.Personal
		v.scope = scopeForProbes(before, node)
		v.deadline = time.Now().Add(20 * time.Second)
		v.slices = 0
		v.candidate.bindPersonalVerification(v.scope, probes)
		selectCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := selectCoreGroupContext(selectCtx, run, candidateGroup, node)
		cancel()
		if err != nil {
			return errors.Join(err, v.close(run))
		}
	}

	node := v.node
	if !time.Now().Before(v.deadline) {
		p.DeferVerification(node, time.Now())
		return v.close(run)
	}
	work, cancel := context.WithDeadline(ctx, v.deadline)
	defer cancel()
	// Incomplete targets get another turn within this candidate's separate
	// budget. The normal channel refresh period does not apply to trials.
	v.candidate.next = time.Time{}
	v.slices++
	err := v.candidate.advance(work, func(c context.Context, p policy.Probe) error {
		return v.ingress.probe(c, run, p, node)
	})
	latest, loadErr := load(run)
	if loadErr != nil {
		return errors.Join(loadErr, v.close(run))
	}
	if guardErr := guard(run, &latest); guardErr != nil {
		return errors.Join(guardErr, v.close(run))
	}
	if scopeForProbes(latest, node) != v.scope || latest.Personal != v.previous {
		return v.close(run)
	}
	h, failure := v.candidate.aggregate("personal", candidateListener, time.Now())
	if h.State != "ready" || err != nil {
		if err == nil && failure == nil && v.slices < v.candidate.personalVerificationSliceLimit() {
			return nil
		}
		notePersonalProbeFailure(p, node, failure)
		closeErr := v.close(run)
		if ctx.Err() != nil {
			return errors.Join(ctx.Err(), closeErr)
		}
		if closeErr != nil || latest.Personal != selector.Reject {
			return closeErr
		}
		return update(run, func(s *State) error {
			if e := guard(run, s); e != nil {
				return e
			}
			if s.Personal == latest.Personal && scopeForProbes(*s, node) == scopeForProbes(latest, node) {
				reason := "probe_incomplete"
				if failure != nil {
					reason = probeReason(failure)
				}
				personalUnavailable(s, reason)
				status := s.Channels["personal"]
				status.ProbeScope = "candidate"
				s.Channels["personal"] = status
			}
			return nil
		})
	}
	// Close the trial before changing live egress. Its measured result is
	// immutable and must remain complete and current under the run lock.
	scope, deadline := v.scope, v.deadline
	if err := v.close(run); err != nil {
		return err
	}
	if err := setVerifiedPersonal(ctx, run, before, node, func(s State) bool {
		now := time.Now()
		return scopeForProbes(s, node) == scope && now.Before(deadline) && !now.Before(h.CheckedAt) && now.Sub(h.CheckedAt) <= probeEvidenceTTL
	}); err != nil {
		if errors.Is(err, errProbeScopeChanged) {
			return nil
		}
		return err
	}
	return v.confirmMixed(ctx, run, before, p, probes, node)
}

func notePersonalProbeFailure(p *selector.Policy, node string, failure error) {
	now := time.Now()
	switch {
	case nodeProbeFailure(failure):
		p.ReportFailure(node, now)
	case probeReason(failure) == "http_status_rejected":
		p.ReportServiceRejection(node, now)
	default:
		p.DeferVerification(node, now)
	}
}

func setVerifiedPersonal(ctx context.Context, run string, before State, node string, fresh func(State) bool) error {
	return update(run, func(s *State) error {
		if err := guard(run, s); err != nil {
			return err
		}
		if s.Personal != before.Personal || scopeForProbes(*s, node) != scopeForProbes(before, node) || fresh != nil && !fresh(*s) {
			return errProbeScopeChanged
		}
		work, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if err := selectPersonalContext(work, run, node); err != nil {
			return err
		}
		s.Personal = node
		delete(s.Channels, "personal")
		if node == selector.Reject {
			personalUnavailable(s, "no_verified_node")
		}
		return nil
	})
}

// A candidate result never supplies real mixed-ingress or TUN evidence.
// Independently check the just-selected mixed route before committing it.
func (v *personalVerification) confirmMixed(ctx context.Context, run string, before State, p *selector.Policy, probes []policy.Probe, node string) error {
	work, cancel := context.WithTimeout(ctx, 18*time.Second)
	defer cancel()
	scope := scopeForProbes(before, node)
	v.mixed.reset()
	v.mixed.bindPersonalVerification(scope, probes)
	var failure error
	for i := 0; i < v.mixed.personalVerificationSliceLimit() && work.Err() == nil; i++ {
		if err := pulse(run); err != nil {
			return err
		}
		v.mixed.next = time.Time{}
		if err := v.mixed.advance(work, func(c context.Context, target policy.Probe) error {
			return probeHTTPIngress(c, run, target, before.Manifest.Config.Ports.Proxy, "", "", "DEFAULT-MIXED", "PERSONAL", node)
		}); err != nil {
			break
		}
		status, err := v.mixed.aggregate("personal", "mixed_ingress", time.Now())
		failure = err
		if failure != nil {
			break
		}
		if status.State == "ready" {
			after, err := load(run)
			if err != nil {
				return err
			}
			if err := guard(run, &after); err != nil {
				return err
			}
			if scopeForProbes(after, node) == scope && after.Personal == node && work.Err() == nil {
				p.ConfirmService(node)
				p.Commit(node, time.Now())
				return nil
			}
			break
		}
	}

	// Restore an observed healthy incumbent if the run and scope still match.
	// Otherwise keep the live personal group closed until another candidate
	// is validated. An incomplete observation is not a measured failure.
	restore := selector.Reject
	if ctx.Err() == nil && before.Personal == p.Current && before.Personal != selector.Reject && channelView(before, "personal", time.Now()).State == "ready" {
		restore = before.Personal
	}
	current := before
	current.Personal = node
	if err := setVerifiedPersonal(context.Background(), run, current, restore, nil); err != nil {
		return err
	}
	if failure == nil {
		notePersonalProbeFailure(p, node, nil)
		p.Commit(restore, time.Now())
		return ctx.Err()
	}
	if restore != selector.Reject {
		notePersonalProbeFailure(p, node, failure)
		return nil
	}
	return recordPersonalRejection(p, node, failure, "mixed_ingress", func(fn func(*State) error) error { return update(run, fn) })
}
