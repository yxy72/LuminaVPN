package engine

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"netlaunch/internal/policy"
)

func TestProbeBatchBoundsWorkAndDoesNotInventFailures(t *testing.T) {
	probes := make([]policy.Probe, 100)
	for i := range probes {
		probes[i] = policy.Probe{Channel: "direct"}
	}
	var active, peak, finished atomic.Int32
	start := time.Now()
	observations := runProbeBatch(context.Background(), probes, 80*time.Millisecond, 4, func(ctx context.Context, p policy.Probe) error {
		count := active.Add(1)
		for old := peak.Load(); count > old && !peak.CompareAndSwap(old, count); old = peak.Load() {
		}
		defer active.Add(-1)
		<-ctx.Done()
		finished.Add(1)
		return ctx.Err()
	})
	if time.Since(start) > time.Second || peak.Load() > 4 || len(observations) != len(probes) {
		t.Fatal("unbounded batch", peak.Load())
	}
	for _, observation := range observations {
		h := observeChannel(ChannelStatus{}, observation.err, observation.checked, observation.probe)
		if h.State != "unknown" || nodeProbeFailure(observation.err) {
			t.Fatal("unfinished probe became failure", h)
		}
	}
	deadline := time.Now().Add(time.Second)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 0 || finished.Load() != peak.Load() {
		t.Fatal("workers did not cancel")
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
