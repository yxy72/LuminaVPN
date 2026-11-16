package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
)

func TestProbeScheduleCoversSlowTailWithoutInventingReadiness(t *testing.T) {
	probes := make([]policy.Probe, 5)
	for i := range probes {
		probes[i] = policy.Probe{Channel: "company"}
	}
	probes[4].URL = "https://tail.example/health"
	check := func(ctx context.Context, _ policy.Probe) error {
		select {
		case <-time.After(320 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s := newProbeSchedule()
	s.sliceBudget, s.targetBudget = 600*time.Millisecond, 500*time.Millisecond
	scope := probeScope{network: platform.Network{Interface: "en0"}, vpn: "vpn-1"}
	s.bind(scope, probes)
	if err := s.advance(context.Background(), check); err != nil {
		t.Fatal(err)
	}
	first, _ := s.aggregate("company", "company_bound", time.Now())
	if first.State != "unknown" || first.Reason != "probe_incomplete" {
		t.Fatalf("four of five successful targets published readiness: %+v", first)
	}
	if err := s.advance(context.Background(), check); err != nil {
		t.Fatal(err)
	}
	all, _ := s.aggregate("company", "company_bound", time.Now())
	if all.State != "ready" || !all.CheckedAt.Equal(first.CheckedAt) {
		t.Fatalf("tail starved or oldest proof was refreshed: %+v", all)
	}
	stale, _ := s.aggregate("company", "company_bound", all.CheckedAt.Add(probeEvidenceTTL+time.Millisecond))
	if stale.State != "unknown" || stale.Reason != "check_expired" {
		t.Fatalf("expired proof still usable: %+v", stale)
	}
	scope.vpn = "vpn-2"
	s.bind(scope, probes)
	if next, _ := s.aggregate("company", "company_bound", time.Now()); next.State != "unknown" || !next.CheckedAt.IsZero() {
		t.Fatalf("new VPN reused old results: %+v", next)
	}
}

func TestProbeScheduleDiscardsLateResultsAndBoundsOutstandingWork(t *testing.T) {
	s := newProbeSchedule()
	s.sliceBudget, s.targetBudget = 25*time.Millisecond, 20*time.Millisecond
	probes := make([]policy.Probe, 5)
	for i := range probes {
		probes[i] = policy.Probe{Channel: "direct"}
	}
	scope := probeScope{network: platform.Network{Gateway: "192.0.2.1"}}
	s.bind(scope, probes)
	started := make(chan struct{}, len(probes))
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	check := func(context.Context, policy.Probe) error {
		started <- struct{}{}
		<-release
		return nil
	}
	if err := s.advance(context.Background(), check); err != nil {
		t.Fatal(err)
	}
	scope.network.Gateway = "192.0.2.2"
	s.bind(scope, probes)
	for i := 0; i < 3; i++ {
		if err := s.advance(context.Background(), check); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.busy) != 4 {
		t.Fatalf("expected hung work to hold four slots, got %d", len(s.busy))
	}
	close(release)
	released = true
	timeout := time.After(time.Second)
	for i := 0; i < 4; i++ {
		select {
		case o := <-s.done:
			s.receive(o, false)
		case <-timeout:
			t.Fatal("workers did not exit")
		}
	}
	if len(started) != 4 {
		t.Fatalf("started %d workers across scope change", len(started))
	}
	if h, _ := s.aggregate("direct", "system_tun", time.Now()); h.State != "unknown" || !h.CheckedAt.IsZero() {
		t.Fatalf("late work verified new scope: %+v", h)
	}
}

func TestProbeScheduleRetainsOnlyFreshMeasuredEvidence(t *testing.T) {
	p := policy.Probe{Channel: "personal", Purpose: "service", ExpectedStatus: []int{204}}
	s := newProbeSchedule()
	s.bind(probeScope{node: "node-a"}, []policy.Probe{p})
	if err := s.advance(context.Background(), func(context.Context, policy.Probe) error { return nil }); err != nil {
		t.Fatal(err)
	}
	before, _ := s.aggregate("personal", "system_tun", time.Now())
	s.next = time.Time{}
	if err := s.advance(context.Background(), func(context.Context, policy.Probe) error { return context.DeadlineExceeded }); err != nil {
		t.Fatal(err)
	}
	if h, failure := s.aggregate("personal", "system_tun", time.Now()); h.State != "ready" || h.CheckedAt != before.CheckedAt || failure != nil {
		t.Fatalf("unfinished work replaced fresh evidence: %+v, %v", h, failure)
	}
	s.next = time.Time{}
	if err := s.advance(context.Background(), func(_ context.Context, p policy.Probe) error { return checkProbeStatus(p, 403) }); err != nil {
		t.Fatal(err)
	}
	if h, failure := s.aggregate("personal", "system_tun", time.Now()); h.State != "unavailable" || h.PathState != "verified" || probeReason(failure) != "http_status_rejected" {
		t.Fatalf("measured refusal did not override old success: %+v, %v", h, failure)
	}
	p.ExpectedStatus[0] = 200
	s.bind(probeScope{node: "node-a"}, []policy.Probe{p})
	if h, failure := s.aggregate("personal", "system_tun", time.Now()); h.State != "unknown" || failure != nil {
		t.Fatalf("changed expected statuses reused old evidence: %+v, %v", h, failure)
	}
}

func TestProbeScheduleCanceledCheckCannotPublishSuccess(t *testing.T) {
	s := newProbeSchedule()
	s.bind(probeScope{}, []policy.Probe{{Channel: "direct"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.advance(ctx, func(context.Context, policy.Probe) error {
		cancel()
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if h, _ := s.aggregate("direct", "system_tun", time.Now()); h.State != "unknown" || !h.CheckedAt.IsZero() {
		t.Fatalf("canceled check published success: %+v", h)
	}
}

func TestChannelSeparatesServiceFailureAndExpiresEvidence(t *testing.T) {
	now := time.Now()
	p := policy.Probe{Channel: "personal", Purpose: "service"}
	h := observeChannel(ChannelStatus{}, checkProbeStatus(p, 503), now, p)
	h = observeChannel(h, nil, now, policy.Probe{Channel: "personal", Purpose: "path"})
	if h.State != "unavailable" || h.PathState != "verified" || h.ServiceState != "failed" || h.NextAction != "check_service_expectation" {
		t.Fatal(h)
	}
	s := healthyState(now)
	s.Personal = "REJECT"
	s.Channels["personal"] = ChannelHealth{ChannelStatus: h, Node: "REJECT", Network: s.Manifest.Network}
	if got := channelView(s, "personal", now); got.NextAction != "check_service_expectation" || got.PathState != "verified" {
		t.Fatal("closed gate erased service diagnosis", got)
	}
	stale := ageProbeEvidence(h, now.Add(91*time.Second))
	if stale.PathState != "unknown" || stale.ServiceState != "unknown" {
		t.Fatal("stale successful path retained", stale)
	}
	for _, err := range []error{context.DeadlineExceeded, newCoreFailure("core_unavailable", errors.New("private detail"))} {
		h = observeChannel(ChannelStatus{}, err, now, p)
		h = observeChannel(h, nil, now, p)
		if h.State != "unknown" || h.PathState != "unknown" || h.ServiceState != "unknown" {
			t.Fatal(h)
		}
	}
	h = observeChannel(ChannelStatus{}, nil, now, p)
	h = observeChannel(h, nil, now, policy.Probe{Channel: "personal", Purpose: "path"})
	if h.State != "ready" || h.ServiceState != "healthy" || h.Reason != "service_healthy" {
		t.Fatal(h)
	}
}
