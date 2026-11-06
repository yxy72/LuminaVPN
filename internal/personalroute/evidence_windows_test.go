//go:build windows

package personalroute

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func failedPool(t *testing.T) Input {
	t.Helper()
	now := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	gen := Generation{Run: "run-1", Network: "network-1", Probe: "sweep-1"}
	ids := []string{"node-b", "node-a"}
	pool, err := PoolID(ids)
	if err != nil {
		t.Fatal(err)
	}
	in := Input{Generation: gen, Candidates: ids, Now: now}
	for _, id := range ids {
		in.Observations = append(in.Observations, Observation{CandidateID: id, PoolID: pool, Generation: gen, Scope: IndependentHealth, Outcome: PathFailed, StartedAt: now.Add(-3 * time.Second), FinishedAt: now.Add(-time.Second)})
	}
	return in
}

func TestEvaluateRequiresCompleteCurrentIndependentFailures(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Input)
		allow  bool
		reason string
	}{
		{"complete failures", func(*Input) {}, true, ReasonAllFailed},
		{"explicit manual off bypasses evidence", func(in *Input) { *in = Input{ManualDisabled: true} }, true, ReasonManualDisabled},
		{"zero input is not manual off", func(in *Input) { *in = Input{} }, false, ReasonInvalidGeneration},
		{"missing run", func(in *Input) { in.Generation.Run = "" }, false, ReasonInvalidGeneration},
		{"missing network", func(in *Input) { in.Generation.Network = "" }, false, ReasonInvalidGeneration},
		{"missing sweep", func(in *Input) { in.Generation.Probe = "" }, false, ReasonInvalidGeneration},
		{"empty pool", func(in *Input) { in.Candidates = nil; in.Observations = nil }, false, ReasonInvalidPool},
		{"duplicate pool", func(in *Input) { in.Candidates[1] = in.Candidates[0] }, false, ReasonInvalidPool},
		{"blank candidate ID", func(in *Input) { in.Candidates[0] = "" }, false, ReasonInvalidPool},
		{"missing current time", func(in *Input) { in.Now = time.Time{} }, false, ReasonInvalidTime},
		{"negative freshness", func(in *Input) { in.MaxAge = -time.Second }, false, ReasonInvalidMaxAge},
		{"cannot widen freshness", func(in *Input) { in.MaxAge = time.Minute }, false, ReasonInvalidMaxAge},
		{"tightened freshness succeeds", func(in *Input) { in.MaxAge = 4 * time.Second }, true, ReasonAllFailed},
		{"tightened freshness expires", func(in *Input) { in.MaxAge = 2 * time.Second }, false, ReasonStale},
		{"next batch is not complete evidence", func(in *Input) { in.Observations = in.Observations[:1] }, false, ReasonIncomplete},
		{"added candidate invalidates old pool", func(in *Input) { in.Candidates = append(in.Candidates, "node-c") }, false, ReasonIncomplete},
		{"removed candidate invalidates surviving evidence", func(in *Input) { in.Candidates = in.Candidates[:1]; in.Observations = in.Observations[:1] }, false, ReasonPoolChanged},
		{"replaced pool member", func(in *Input) { in.Candidates[1] = "node-c"; in.Observations[1].CandidateID = "node-c" }, false, ReasonPoolChanged},
		{"changed then reverted pool still requires new sweep", func(in *Input) { in.Generation.Probe = "sweep-after-pool-change" }, false, ReasonGenerationChanged},
		{"different run", func(in *Input) { in.Observations[0].Generation.Run = "old-run" }, false, ReasonGenerationChanged},
		{"different network", func(in *Input) { in.Observations[0].Generation.Network = "old-network" }, false, ReasonGenerationChanged},
		{"different sweep", func(in *Input) { in.Observations[0].Generation.Probe = "old-sweep" }, false, ReasonGenerationChanged},
		{"missing pool binding", func(in *Input) { in.Observations[0].PoolID = "" }, false, ReasonPoolChanged},
		{"single target failure", func(in *Input) { in.Observations[0].Scope = TargetRequest }, false, ReasonWrongScope},
		{"missing scope", func(in *Input) { in.Observations[0].Scope = "" }, false, ReasonWrongScope},
		{"healthy candidate prevents direct", func(in *Input) { in.Observations[1].Outcome = Healthy }, false, ReasonHealthy},
		{"canceled check", func(in *Input) { in.Observations[0].Outcome = Canceled }, false, ReasonUnconfirmed},
		{"unknown controller result", func(in *Input) { in.Observations[0].Outcome = Unknown }, false, ReasonUnconfirmed},
		{"HTTP service failure is not path failure", func(in *Input) { in.Observations[0].Outcome = ServiceFailed }, false, ReasonUnconfirmed},
		{"missing outcome", func(in *Input) { in.Observations[0].Outcome = "" }, false, ReasonUnconfirmed},
		{"unsupported outcome", func(in *Input) { in.Observations[0].Outcome = "REJECT" }, false, ReasonUnconfirmed},
		{"duplicate evidence cannot replace missing member", func(in *Input) { in.Observations[1] = in.Observations[0] }, false, ReasonInvalidEvidence},
		{"evidence from unlisted member", func(in *Input) { in.Observations[1].CandidateID = "node-c" }, false, ReasonIncomplete},
		{"invalid evidence ID", func(in *Input) { in.Observations[0].CandidateID = "" }, false, ReasonInvalidEvidence},
		{"extra evidence is not silently ignored", func(in *Input) { in.Observations = append(in.Observations, in.Observations[0]) }, false, ReasonIncomplete},
		{"missing start", func(in *Input) { in.Observations[0].StartedAt = time.Time{} }, false, ReasonInvalidTime},
		{"missing finish", func(in *Input) { in.Observations[0].FinishedAt = time.Time{} }, false, ReasonInvalidTime},
		{"finish before start", func(in *Input) { in.Observations[0].FinishedAt = in.Observations[0].StartedAt.Add(-time.Second) }, false, ReasonInvalidTime},
		{"future finish", func(in *Input) { in.Observations[0].FinishedAt = in.Now.Add(time.Nanosecond) }, false, ReasonInvalidTime},
		{"future start", func(in *Input) {
			in.Observations[0].StartedAt = in.Now.Add(time.Nanosecond)
			in.Observations[0].FinishedAt = in.Now.Add(time.Second)
		}, false, ReasonInvalidTime},
		{"long running stale check", func(in *Input) { in.Observations[0].StartedAt = in.Now.Add(-time.Minute) }, false, ReasonStale},
		{"exact freshness boundary is stale", func(in *Input) { in.Observations[0].StartedAt = in.Now.Add(-DefaultMaxAge) }, false, ReasonStale},
		{"expired completed check", func(in *Input) { in.Now = in.Now.Add(time.Minute) }, false, ReasonStale},
		{"just inside freshness bound", func(in *Input) { in.Observations[0].StartedAt = in.Now.Add(-DefaultMaxAge + time.Nanosecond) }, true, ReasonAllFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := failedPool(t)
			tc.change(&in)
			got := Evaluate(in)
			if got.DirectAllowed != tc.allow || got.Reason != tc.reason {
				t.Fatalf("Evaluate = %+v, want allowed=%v reason=%s", got, tc.allow, tc.reason)
			}
		})
	}
}

func TestPoolIDBindsMembersWithoutMutatingInput(t *testing.T) {
	a := []string{"node-b", "node-a"}
	before := append([]string(nil), a...)
	first, err := PoolID(a)
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := PoolID([]string{"node-a", "node-b"})
	if err != nil || first != reordered || len(first) != 64 {
		t.Fatalf("pool identity must be a canonical SHA256: %q %q %v", first, reordered, err)
	}
	if !reflect.DeepEqual(a, before) {
		t.Fatal("PoolID mutated candidate order")
	}
	left, _ := PoolID([]string{"ab", "c"})
	right, _ := PoolID([]string{"a", "bc"})
	if left == right {
		t.Fatal("pool identity must delimit opaque IDs")
	}
	for _, ids := range [][]string{nil, {"a", "a"}, {""}, {" leading"}, {"trailing "}, {"line\nbreak"}, {"nul\x00id"}, {strings.Repeat("x", 257)}} {
		if _, err := PoolID(ids); err == nil {
			t.Errorf("accepted malformed candidate pool %q", ids)
		}
	}
}

func TestEvaluateIsStatelessAndDoesNotMutateEvidence(t *testing.T) {
	in := failedPool(t)
	before := in
	before.Candidates = append([]string(nil), in.Candidates...)
	before.Observations = append([]Observation(nil), in.Observations...)
	want := Decision{DirectAllowed: true, Reason: ReasonAllFailed}
	if got := Evaluate(in); got != want {
		t.Fatal(got)
	}
	if !reflect.DeepEqual(in, before) {
		t.Fatal("Evaluate mutated its input")
	}
	// An unrelated evaluation cannot authorize a later incomplete observation.
	if got := Evaluate(Input{ManualDisabled: true}); !got.DirectAllowed {
		t.Fatal(got)
	}
	in.Observations = nil
	if got := Evaluate(in); got.DirectAllowed || got.Reason != ReasonIncomplete {
		t.Fatal(got)
	}
	if got := Evaluate(before); got != want {
		t.Fatal(got)
	}
}
