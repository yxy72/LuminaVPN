package selector

import (
	"testing"
	"time"
)

func TestServiceRejectionsPreserveReachabilityAndDoNotStarveSelection(t *testing.T) {
	p := New([]string{"fast", "medium", "slow"})
	t0 := time.Unix(1000, 0)
	paths := map[string]int{"fast": 20, "medium": 100, "slow": 200}
	node, _ := p.DecideSamples(t0, paths)
	if node != "fast" {
		t.Fatal(node)
	}
	p.ReportServiceRejection(node, t0)
	if h := p.health[node]; !h.FailedAt.IsZero() || h.Latency != 20 || h.Observed != t0 {
		t.Fatalf("service rejection modified path evidence: %+v", h)
	}
	node, _ = p.DecideSamples(t0.Add(time.Second), paths)
	if node != "medium" {
		t.Fatal(node)
	}
	p.ReportServiceRejection(node, t0.Add(time.Second))
	// Both rejected nodes are past the hold. The untested, slower node still
	// gets a chance, and a usable selection stays in place during later rounds.
	later := t0.Add(20 * time.Second)
	node, _ = p.DecideSamples(later, paths)
	if node != "slow" {
		t.Fatal("a rejected node starved an untested one", node)
	}
	p.ConfirmService(node)
	p.Commit(node, later)
	later = later.Add(time.Minute)
	paths["slow"] = 500
	for range 4 {
		node, _ = p.DecideSamples(later, paths)
		if node != "slow" {
			t.Fatal("path success caused another live switch to a known service reject", node)
		}
		later = later.Add(time.Second)
	}

	paths["slow"] = -1
	node, _ = p.DecideSamples(later, paths)
	if node != "fast" {
		t.Fatal("oldest rejection was not retried when the other path failed", node)
	}
	p.ReportServiceRejection(node, later)
	node, _ = p.DecideSamples(later.Add(time.Second), paths)
	if node != "medium" {
		t.Fatal("the recovering pool repeated the same service reject", node)
	}
	p.ConfirmService(node)
	if h := p.health[node]; !h.ServiceRejectedAt.IsZero() || h.Latency != 100 || !h.FailedAt.IsZero() {
		t.Fatalf("a recovered service did not regain normal eligibility: %+v", h)
	}
}
