package engine

import (
	"context"
	"errors"
	"slices"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
)

const probeEvidenceTTL = 90 * time.Second

// One schedule belongs to one coordinator and one ingress. A snapshot cannot
// be applied after the network, VPN, selected node or applied intent changes.
type probeScope struct {
	runDigest       string
	network         platform.Network
	binding         policy.Binding
	wakeEpoch       string
	powerEpoch      uint64
	vpn, node       string
	vpnReady        bool
	intent, applied uint64
	fallback        bool
}

func scopeForProbes(s State, node string) probeScope {
	scope := probeScope{
		runDigest: s.RunSpecDigest, network: s.Manifest.Network, binding: s.Manifest.Binding,
		wakeEpoch: s.VPN.WakeEpoch, vpn: s.VPN.Generation, vpnReady: s.VPN.Bootstrap,
		node: node, intent: s.ChannelGeneration, applied: s.AppliedGeneration, fallback: s.PersonalFallback,
	}
	if s.Windows != nil {
		scope.powerEpoch = s.Windows.Epoch
	}
	return scope
}

type probeResult struct {
	index       int
	slice       uint64
	observation probeObservation
	completed   bool
}

type probeObservation struct {
	err     error
	checked time.Time
}

type probeSchedule struct {
	scope        probeScope
	probes       []policy.Probe
	observations []probeObservation
	cursor       int
	slice        uint64
	busy         map[int]bool
	done         chan probeResult
	next         time.Time
	parallel     int
	sliceBudget  time.Duration
	targetBudget time.Duration
}

func newProbeSchedule() *probeSchedule {
	return &probeSchedule{
		busy: make(map[int]bool), done: make(chan probeResult, 4), parallel: 4,
		sliceBudget: 6 * time.Second, targetBudget: 5 * time.Second,
	}
}

func sameProbe(a, b policy.Probe) bool {
	return a.URL == b.URL && a.Channel == b.Channel && a.Purpose == b.Purpose && slices.Equal(a.ExpectedStatus, b.ExpectedStatus)
}

func (s *probeSchedule) reset() {
	s.probes, s.observations = nil, nil
	s.cursor, s.next = 0, time.Time{}
	// Workers that did not honor cancellation still own their slots. Drain
	// their results before reusing the slots and discard their old evidence.
}

func (s *probeSchedule) bind(scope probeScope, probes []policy.Probe) {
	if s.scope == scope && slices.EqualFunc(s.probes, probes, sameProbe) {
		return
	}
	s.reset()
	s.scope = scope
	s.probes = slices.Clone(probes)
	for i := range s.probes {
		s.probes[i].ExpectedStatus = slices.Clone(s.probes[i].ExpectedStatus)
	}
	s.observations = make([]probeObservation, len(probes))
}

func (s *probeSchedule) due(now time.Time) bool {
	return !now.Before(s.next)
}

func (s *probeSchedule) receive(r probeResult, current bool) {
	delete(s.busy, r.index)
	if current && r.completed {
		s.observations[r.index] = r.observation
	}
}

func (s *probeSchedule) drain() {
	for {
		select {
		case r := <-s.done:
			s.receive(r, false)
		default:
			return
		}
	}
}

// Advance one slice of a rotating scan. A late callback never publishes an
// observation, and new slices cannot exceed the fixed limit on outstanding work.
func (s *probeSchedule) advance(parent context.Context, check func(context.Context, policy.Probe) error) error {
	s.drain()
	if parent.Err() != nil || !s.due(time.Now()) || len(s.probes) == 0 {
		return parent.Err()
	}
	work, cancel := context.WithTimeout(parent, s.sliceBudget)
	defer cancel()
	s.slice++
	slice := s.slice
	running := 0
	for s.cursor < len(s.probes) && len(s.busy) < s.parallel && work.Err() == nil {
		index := s.cursor
		s.cursor++
		if s.busy[index] {
			continue
		}
		s.busy[index] = true
		running++
		p := s.probes[index]
		go func() {
			target, stop := context.WithTimeout(work, s.targetBudget)
			defer stop()
			err := check(target, p)
			at := time.Now()
			completed := target.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
			s.done <- probeResult{index, slice, probeObservation{err, at}, completed}
		}()
	}
	if s.cursor == len(s.probes) {
		s.cursor = 0
		s.next = time.Now().Add(30 * time.Second)
	}
	for running > 0 {
		select {
		case r := <-s.done:
			current := r.slice == slice
			if current {
				running--
			}
			s.receive(r, current && parent.Err() == nil)
		case <-work.Done():
			// A slice deadline is missing evidence. Late work will be drained
			// next time and must not replace a still-valid observation.
			return parent.Err()
		}
	}
	return parent.Err()
}

// Aggregation applies to all required targets. The oldest contributing
// timestamp is the upper bound for the freshness of the aggregate.
func (s *probeSchedule) aggregate(channel, ingress string, now time.Time) (ChannelStatus, error) {
	var status ChannelStatus
	var oldest time.Time
	var failure error
	for i, p := range s.probes {
		if p.Channel != channel {
			continue
		}
		o := s.observations[i]
		fresh := !o.checked.IsZero() && !now.Before(o.checked) && now.Sub(o.checked) <= probeEvidenceTTL
		if fresh {
			status = observeChannel(status, o.err, o.checked, p)
			if oldest.IsZero() || o.checked.Before(oldest) {
				oldest = o.checked
			}
			if err := o.err; err != nil && (failure == nil || nodeProbeFailure(err)) {
				var core *coreFailure
				if !errors.As(err, &core) {
					failure = err
				}
			}
			continue
		}
		reason := "probe_incomplete"
		if !o.checked.IsZero() {
			reason = "check_expired"
		}
		status = mergeChannelStatus(status, ChannelStatus{
			State: "unknown", Reason: reason, NextAction: "wait_for_probe", PathState: "unknown",
			ServiceState: unknownServiceState(p),
		})
	}
	if status.State == "" {
		status = ChannelStatus{State: "unknown", Reason: "probe_missing", NextAction: "wait_for_probe"}
	}
	status.CheckedAt, status.ProbeScope = oldest, ingress
	return status, failure
}

func unknownServiceState(p policy.Probe) string {
	if p.EffectivePurpose() == "service" {
		return "unknown"
	}
	return "not_checked"
}
