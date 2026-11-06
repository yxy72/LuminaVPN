package selector

import (
	"testing"
	"time"
)

func TestTimedSamplesAdmitFreshNodeWithoutBorrowingSlowNodeStart(t *testing.T) {
	t0 := time.Now().Add(-10 * time.Second)
	p := New([]string{"A", "B"})
	p.DecideTimedSamples(t0.Add(2*time.Second), map[string]TimedSample{"A": {Latency: 100, StartedAt: t0, FinishedAt: t0.Add(2 * time.Second)}})
	p.ReportFailure("B", t0.Add(2*time.Second))
	now := t0.Add(4 * time.Second)
	node, _ := p.DecideTimedSamples(now, map[string]TimedSample{
		"A": {Latency: 12, StartedAt: t0.Add(3 * time.Second), FinishedAt: now},
		"B": {Latency: 1, StartedAt: t0.Add(time.Second), FinishedAt: now},
	})
	if node != "A" || p.health["A"].Latency != 12 || !p.health["A"].Observed.Equal(now) {
		t.Fatal("fresh A was lost because B started earlier")
	}
	if p.health["B"].Successes != 0 || !p.health["B"].FailedAt.Equal(t0.Add(2*time.Second)) {
		t.Fatal("old B check cleared a newer real failure")
	}
}

func TestTimedSamplesRejectFutureStaleInvalidAndReplay(t *testing.T) {
	now := time.Now()
	for _, sample := range []TimedSample{
		{Latency: 1},
		{Latency: 1, StartedAt: now.Add(time.Second), FinishedAt: now.Add(2 * time.Second)},
		{Latency: 1, StartedAt: now.Add(-time.Second), FinishedAt: now.Add(time.Second)},
		{Latency: 1, StartedAt: now, FinishedAt: now.Add(-time.Second)},
		{Latency: 1, StartedAt: now.Add(-45 * time.Second), FinishedAt: now},
	} {
		p := New([]string{"A"})
		if node, _ := p.DecideTimedSamples(now, map[string]TimedSample{"A": sample}); node != Reject {
			t.Fatal("invalid or stale interval became ranked healthy")
		}
	}
	p := New([]string{"A"})
	sample := TimedSample{Latency: 1, StartedAt: now, FinishedAt: now}
	p.DecideTimedSamples(now, map[string]TimedSample{"A": sample})
	p.DecideTimedSamples(now, map[string]TimedSample{"A": sample})
	if p.health["A"].Successes != 1 {
		t.Fatal("coalesced duplicate counted as a new success")
	}
}

func TestTimedSamplesKeepActualEvidenceAge(t *testing.T) {
	now := time.Now()
	p := New([]string{"A"})
	finished := now.Add(-39 * time.Second)
	p.DecideTimedSamples(now, map[string]TimedSample{"A": {Latency: 1, StartedAt: now.Add(-40 * time.Second), FinishedAt: finished}})
	if !p.health["A"].Observed.Equal(finished) {
		t.Fatal("receipt renewed an old observation")
	}
	if node, _ := p.DecideTimedSamples(now.Add(6*time.Second), nil); node != Reject {
		t.Fatal("old health remained fresh after its real deadline")
	}
}
