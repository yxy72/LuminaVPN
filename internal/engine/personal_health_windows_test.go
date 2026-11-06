//go:build windows

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"netlaunch/internal/personalroute"
	"netlaunch/internal/policy"
)

func TestIndependentHealthPreservesTypedFailureScope(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure error
		history bool
		want    personalroute.Outcome
	}{{"path503", &coreFailure{status: 503}, false, personalroute.PathFailed}, {"path504", &coreFailure{status: 504}, false, personalroute.PathFailed}, {"controller401", &coreFailure{status: 401}, false, personalroute.Unknown}, {"controller500", &coreFailure{status: 500}, false, personalroute.Unknown}, {"controller_transport", errors.New("unavailable"), false, personalroute.Unknown}, {"missing_history", nil, false, personalroute.Unknown}, {"path_healthy_even_business_expectation_differs", nil, true, personalroute.Healthy}} {
		t.Run(tc.name, func(t *testing.T) {
			request := func(ctx context.Context, path string, out any) error {
				var raw []byte
				if strings.Contains(path, "/delay?") {
					u, _ := url.Parse(path)
					if u.Query().Get("expected") != "200-599" {
						t.Fatal("business status expectations contaminated health")
					}
					if tc.failure != nil {
						return tc.failure
					}
					raw = []byte(`{"delay":12}`)
				} else {
					raw = []byte(`{}`)
					if tc.history {
						raw, _ = json.Marshal(map[string]any{"extra": map[string]any{"https://health.example/": map[string]any{"alive": true, "history": []any{map[string]any{"time": time.Now(), "delay": 12}}}}})
					}
				}
				return json.Unmarshal(raw, out)
			}
			got := independentNode(context.Background(), "P001", "id", "pool", personalroute.Generation{Run: "r", Network: "n", Probe: "p"}, []string{"https://health.example/"}, request)
			if got.Observation.Outcome != tc.want {
				t.Fatal(got.Observation.Outcome, tc.want)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := independentNode(ctx, "P001", "id", "pool", personalroute.Generation{}, []string{"https://health.example/"}, func(context.Context, string, any) error { return context.Canceled })
	if got.Observation.Outcome != personalroute.Canceled {
		t.Fatal("cancellation became failed path")
	}
}

func independentSchedulerNodes(count int) []policy.Node {
	nodes := make([]policy.Node, count)
	for n := range nodes {
		nodes[n] = policy.Node{"name": fmt.Sprintf("P%03d", n+1), "server": fmt.Sprintf("192.0.2.%d", n%254+1)}
	}
	return nodes
}

func TestIndependentSchedulerFairMultiTargetCoverage(t *testing.T) {
	nodes := independentSchedulerNodes(70) // More nodes than the worker bound.
	probes := []string{"https://one.example/", "https://two.example/", "https://three.example/"}
	g := personalroute.Generation{Run: "r", Network: "n", Probe: "p"}
	scheduler := newIndependentScheduler(nodes, probes, g, personalroute.IndependentHealth)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var mu sync.Mutex
	seen := map[string]bool{}
	var active, peak atomic.Int32
	stream := scheduler.start(ctx, func(ctx context.Context, path string, out any) error {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		u, _ := url.Parse(path)
		mu.Lock()
		seen[u.Path+"?"+u.Query().Get("url")] = true
		mu.Unlock()
		timer := time.NewTimer(2 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return &coreFailure{status: 504}
		}
	})
	complete := false
	for result := range stream {
		decision := fallbackDecisionWithCoverage(policy.ChannelIntent{Personal: true}, nodes, g, result.Samples, time.Now(), result.CoverageReason)
		if decision.DirectAllowed {
			complete = true
			cancel()
		}
	}
	mu.Lock()
	count := len(seen)
	mu.Unlock()
	if !complete || count != len(nodes)*len(probes) {
		t.Fatalf("full node/target coverage missing: complete=%v measured=%d", complete, count)
	}
	if peak.Load() > independentParallel || active.Load() != 0 {
		t.Fatal("worker limit or cancellation drain failed", peak.Load(), active.Load())
	}
}

func TestIndependentSchedulerAdvancesAfterPerTargetTimeouts(t *testing.T) {
	nodes := independentSchedulerNodes(40)
	g := personalroute.Generation{Run: "r", Network: "n", Probe: "p"}
	scheduler := newIndependentScheduler(nodes, []string{"https://one.example/", "https://two.example/", "https://three.example/"}, g, personalroute.IndependentHealth)
	scheduler.parallel, scheduler.batchLimit, scheduler.targetTimeout = 4, 8, 2*time.Millisecond
	scheduler.batchDelay = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var mu sync.Mutex
	seen := map[string]bool{}
	stream := scheduler.start(ctx, func(ctx context.Context, path string, out any) error {
		u, _ := url.Parse(path)
		mu.Lock()
		seen[u.Path+"?"+u.Query().Get("url")] = true
		mu.Unlock()
		<-ctx.Done()
		return ctx.Err()
	})
	covered := false
	for result := range stream {
		if fallbackDecisionWithCoverage(policy.ChannelIntent{Personal: true}, nodes, g, result.Samples, time.Now(), result.CoverageReason).DirectAllowed {
			t.Fatal("per-target cancellation became path failure")
		}
		mu.Lock()
		count := len(seen)
		mu.Unlock()
		if count == len(scheduler.jobs) {
			covered = true
			cancel()
		}
	}
	if !covered {
		t.Fatal("bounded batch restart starved tail nodes/targets")
	}
}

func TestIndependentSchedulerBudgetAndGenerationAreExplicit(t *testing.T) {
	nodes := independentSchedulerNodes(90)
	g := personalroute.Generation{Run: "r", Network: "n", Probe: "p"}
	scheduler := newIndependentScheduler(nodes, []string{"https://one.example/", "https://two.example/", "https://three.example/"}, g, personalroute.IndependentHealth)
	now := time.Now()
	for n := range scheduler.progress {
		for p := range scheduler.progress[n] {
			scheduler.progress[n][p] = independentSample{Observation: personalroute.Observation{CandidateID: scheduler.ids[n], PoolID: scheduler.pool, Generation: g, Scope: personalroute.IndependentHealth, Outcome: personalroute.PathFailed, StartedAt: now.Add(-time.Second), FinishedAt: now}}
		}
	}
	r := scheduler.snapshot(now)
	if r.CoverageReason != "independent_health_coverage_budget_exceeded" || fallbackDecisionWithCoverage(policy.ChannelIntent{Personal: true}, nodes, g, r.Samples, now, r.CoverageReason).DirectAllowed {
		t.Fatal("unsupported worst-case freshness budget authorized fallback")
	}
	if newIndependentScheduler(independentSchedulerNodes(256), []string{"https://one.example/"}, g, personalroute.IndependentHealth).coverageReason != "" {
		t.Fatal("full supported 256-node pool was excluded")
	}
	g.Probe = "new-even-if-pool-returns"
	fresh := newIndependentScheduler(nodes, scheduler.targets, g, personalroute.IndependentHealth).snapshot(now)
	for _, sample := range fresh.Samples {
		if sample.Observation.Generation != g || sample.Observation.Outcome != personalroute.Unknown || !sample.Observation.StartedAt.IsZero() {
			t.Fatal("new generation reused old progress")
		}
	}
}

func TestIndependentSchedulerSlowConsumerDoesNotBlockWork(t *testing.T) {
	scheduler := newIndependentScheduler(independentSchedulerNodes(70), []string{"https://one.example/"}, personalroute.Generation{Run: "r", Network: "n", Probe: "p"}, personalroute.IndependentHealth)
	ctx, cancel := context.WithCancel(context.Background())
	var count atomic.Int32
	completed := make(chan struct{}, 1)
	stream := scheduler.start(ctx, func(context.Context, string, any) error {
		if count.Add(1) == 70 {
			completed <- struct{}{}
		}
		return &coreFailure{status: 504}
	})
	select {
	case <-completed:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("unread snapshot stream blocked checks")
	}
	cancel()
	for range stream {
	}
}

func TestIndependentSchedulerRejectsFutureAndInvertedTargetEvidence(t *testing.T) {
	now := time.Now()
	s := newIndependentScheduler(independentSchedulerNodes(1), []string{"https://one.example/"}, personalroute.Generation{Run: "r", Network: "n", Probe: "p"}, personalroute.IndependentHealth)
	for _, interval := range [][2]time.Time{{now.Add(time.Second), now.Add(2 * time.Second)}, {now.Add(-time.Second), now.Add(time.Second)}, {now, now.Add(-time.Second)}} {
		s.progress[0][0] = independentSample{Latency: 1, Observation: personalroute.Observation{Outcome: personalroute.Healthy, StartedAt: interval[0], FinishedAt: interval[1]}}
		if s.snapshot(now).Samples[0].Observation.Outcome != personalroute.Unknown {
			t.Fatal("clock rollback/future target evidence became ranked healthy")
		}
	}
}

func TestIndependentSchedulerOverBudgetErrorsDoNotSpin(t *testing.T) {
	s := newIndependentScheduler(independentSchedulerNodes(90), []string{"https://one.example/", "https://two.example/", "https://three.example/"}, personalroute.Generation{Run: "r", Network: "n", Probe: "p"}, personalroute.IndependentHealth)
	s.batchDelay = 250 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var requests atomic.Int32
	batchComplete := make(chan struct{}, 1)
	stream := s.start(ctx, func(context.Context, string, any) error {
		if requests.Add(1) == independentCoverageBudget {
			batchComplete <- struct{}{}
		}
		return &coreFailure{status: 401}
	})
	select {
	case <-batchComplete:
	case <-time.After(2 * time.Second):
		t.Fatal("first batch did not finish")
	}
	// Deliberately do not consume snapshots, as with a stalled core/UI check.
	time.Sleep(25 * time.Millisecond)
	if got := requests.Load(); got != independentCoverageBudget {
		t.Fatal("over-budget controller failure spun into another batch", got)
	}
	cancel()
	for range stream {
	}
}

func TestIndependentHealthExcludesBusinessAndOtherChannels(t *testing.T) {
	probes := []policy.Probe{{Channel: "personal", URL: "https://path.example/", Purpose: "path"}, {Channel: "personal", URL: "https://business.example/", Purpose: "service"}, {Channel: "company", URL: "https://company.example/", Purpose: "path"}}
	got := independentProbeTargets(probes)
	if len(got) != 1 || got[0] != "https://path.example/" {
		t.Fatal("business/target mapping contaminated independent health", got)
	}
	sample := independentNode(context.Background(), "P001", "id", "pool", personalroute.Generation{}, nil, func(context.Context, string, any) error { t.Fatal("empty health pool called a target"); return nil })
	if sample.Observation.Outcome != personalroute.Unknown {
		t.Fatal("missing independent target became a failed path")
	}
	targets, scope := personalMeasurementTargets([]policy.Probe{{Channel: "personal", URL: "https://legacy-business.example/"}})
	if len(targets) != 1 || scope != personalroute.TargetRequest {
		t.Fatal("legacy service-only ranking became independent fallback evidence")
	}
}
func TestFallbackAdapterUsesCompleteConfigBoundPool(t *testing.T) {
	nodes := []policy.Node{{"name": "P001", "server": "192.0.2.10"}, {"name": "P002", "server": "192.0.2.11"}}
	ids, names := candidateIDs(nodes)
	pool, _ := personalroute.PoolID(ids)
	g := personalroute.Generation{Run: "run", Network: "network", Probe: "unique-probe"}
	now := time.Now()
	samples := []independentSample{}
	for name, id := range names {
		samples = append(samples, independentSample{Name: name, ID: id, Observation: personalroute.Observation{CandidateID: id, PoolID: pool, Generation: g, Scope: personalroute.IndependentHealth, Outcome: personalroute.PathFailed, StartedAt: now.Add(-time.Second), FinishedAt: now}})
	}
	intent := policy.ChannelIntent{Personal: true}
	if !fallbackDecision(intent, nodes, g, samples, now).DirectAllowed {
		t.Fatal("complete explicit failures denied")
	}
	samples[0].Observation.Scope = personalroute.TargetRequest
	if fallbackDecision(intent, nodes, g, samples, now).DirectAllowed {
		t.Fatal("a single target mapping failure authorized direct fallback")
	}
	samples[0].Observation.Scope = personalroute.IndependentHealth
	if fallbackDecision(intent, nodes, g, samples[:1], now).DirectAllowed {
		t.Fatal("NextBatch subset authorized direct")
	}
	samples[0].Observation.Outcome = personalroute.Unknown
	if fallbackDecision(intent, nodes, g, samples, now).DirectAllowed {
		t.Fatal("unknown authorized direct")
	}
	samples[0].Observation.Outcome = personalroute.PathFailed
	g.Probe = "new-probe-even-if-pool-changed-back"
	if fallbackDecision(intent, nodes, g, samples, now).DirectAllowed {
		t.Fatal("old generation authorized direct")
	}
	if !fallbackDecision(policy.ChannelIntent{}, nil, personalroute.Generation{}, nil, now).DirectAllowed {
		t.Fatal("explicit manual off denied")
	}
}
