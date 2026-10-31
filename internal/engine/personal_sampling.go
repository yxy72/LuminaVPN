//go:build darwin || windows

package engine

import (
	"context"
	"time"

	"netlaunch/internal/selector"
)

type personalMeasurements struct {
	values   map[string]int
	started  time.Time
	finished time.Time
}

// Only the coordinator accesses this state or the selector. Workers publish
// immutable measurements and never select a group or update run state.
type personalSampling struct {
	policy *selector.Policy
	done   chan personalMeasurements
	cancel context.CancelFunc
}

func (s *personalSampling) close() {
	if s.cancel != nil {
		s.cancel()
	}
	s.done = nil
	s.cancel = nil
}

func (s *personalSampling) refresh(ctx context.Context, run string, policy *selector.Policy) (bool, error) {
	if s.policy != policy {
		s.close()
		s.policy = policy
	}
	if s.done == nil {
		probes, err := personalProbeURLs(run)
		if err != nil {
			return false, err
		}
		names := policy.NextBatch(8)
		work, cancel := context.WithCancel(ctx)
		done := make(chan personalMeasurements, 1)
		s.cancel, s.done = cancel, done
		started := time.Now()
		go func() { done <- personalMeasurements{measurePersonal(work, run, names, probes), started, time.Now()} }()
		return false, nil
	}
	select {
	case <-ctx.Done():
		s.close()
		return false, ctx.Err()
	case measured := <-s.done:
		s.close()
		if time.Since(measured.finished) > 10*time.Second {
			return false, nil
		}
		return true, applyPersonalSamples(ctx, run, policy, measured.started, measured.values)
	default:
		return false, nil
	}
}
