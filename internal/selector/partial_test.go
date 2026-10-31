package selector

import (
	"testing"
	"time"
)

func TestPartialMeasurementsExpireWithoutInventingFailures(t *testing.T) {
	p := New([]string{"a", "b"})
	now := time.Unix(1000, 0)
	node, _ := p.DecideSamples(now, map[string]int{"a": 100})
	p.Commit(node, now)
	if node != "a" {
		t.Fatal(node)
	}
	node, _ = p.DecideSamples(now.Add(time.Second), nil)
	if node != "a" || !p.health["b"].FailedAt.IsZero() {
		t.Fatal("unknown treated as failed", node)
	}
	node, _ = p.DecideSamples(now.Add(45*time.Second), nil)
	if node != Reject {
		t.Fatal("stale success retained", node)
	}
	// Unknown observations did not put this previously unmeasured node into cooldown.
	node, _ = p.DecideSamples(now.Add(46*time.Second), map[string]int{"b": 10})
	if node != "b" {
		t.Fatal(node)
	}
}

func TestPartialSamplesDoNotReuseConfirmationOrFailureEvidence(t *testing.T) {
	p := New([]string{"a", "b"})
	p.Options.MinHold = 0
	now := time.Unix(1000, 0)
	p.Commit("a", now)
	p.DecideSamples(now, map[string]int{"a": 500, "b": 10})
	for i := 1; i < 5; i++ {
		node, _ := p.DecideSamples(now.Add(time.Duration(i)*time.Second), nil)
		if node != "a" {
			t.Fatal("cached result counted as fresh confirmation")
		}
	}
	p.ReportFailure("a", now.Add(5*time.Second))
	node, _ := p.DecideSamples(now.Add(6*time.Second), nil)
	if node == "a" {
		t.Fatal("known failed node retained")
	}
}

func TestRotatingBatchesRetestCurrentAndCoverEveryCandidate(t *testing.T) {
	p := New([]string{"a", "b", "c", "d", "e"})
	p.Commit("c", time.Now())
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		batch := p.NextBatch(3)
		if len(batch) != 3 || batch[0] != "c" {
			t.Fatal(batch)
		}
		local := map[string]bool{}
		for _, n := range batch {
			if local[n] {
				t.Fatal("duplicate", batch)
			}
			local[n] = true
			seen[n] = true
		}
	}
	if len(seen) != len(p.Nodes) {
		t.Fatal(seen)
	}
}

func TestLateMeasurementCannotOverrideNewerRequestFailure(t *testing.T) {
	p := New([]string{"a"})
	now := time.Unix(1000, 0)
	p.Commit("a", now)
	p.ReportFailure("a", now.Add(time.Second))
	for i := 0; i < 4; i++ {
		node, _ := p.DecideSamplesSince(now.Add(20*time.Second), now, map[string]int{"a": 1})
		if node != Reject || p.health["a"].Successes != 0 {
			t.Fatal("late round revived failed node")
		}
	}
}

func TestPendingCandidateGetsFreshConfirmationsWithoutStarvingRotation(t *testing.T) {
	p := New([]string{"a", "b", "c", "d", "e"})
	p.Options.MinHold = 0
	now := time.Unix(1000, 0)
	p.Commit("a", now)
	p.DecideSamples(now, map[string]int{"a": 500, "b": 10})
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		batch := p.NextBatch(3)
		if len(batch) != 3 || batch[0] != "a" || batch[1] != "b" {
			t.Fatal(batch)
		}
		seen[batch[2]] = true
	}
	if !seen["c"] || !seen["d"] || !seen["e"] {
		t.Fatal("candidate confirmation starved rotation", seen)
	}
}
