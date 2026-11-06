//go:build windows

package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sync"
	"time"

	"netlaunch/internal/personalroute"
	"netlaunch/internal/policy"
	"netlaunch/internal/selector"
)

type independentSample struct {
	Name, ID    string
	Observation personalroute.Observation
	Latency     int
}
type independentSweep struct {
	Generation     personalroute.Generation
	Samples        []independentSample
	Started        time.Time
	CoverageReason string
}

func independentProbeTargets(probes []policy.Probe) []string {
	var targets []string
	for _, probe := range probes {
		if probe.Channel == "personal" && probe.EffectivePurpose() == "path" {
			targets = append(targets, probe.URL)
		}
	}
	return targets
}

func personalMeasurementTargets(probes []policy.Probe) ([]string, personalroute.Scope) {
	if targets := independentProbeTargets(probes); len(targets) != 0 {
		return targets, personalroute.IndependentHealth
	}
	// Compatibility ranking can still use service targets, but their failure
	// never constitutes independent evidence authorizing a direct fallback.
	var targets []string
	for _, probe := range probes {
		if probe.Channel == "personal" {
			targets = append(targets, probe.URL)
		}
	}
	return targets, personalroute.TargetRequest
}

func candidateIDs(nodes []policy.Node) ([]string, map[string]string) {
	ids := make([]string, 0, len(nodes))
	names := map[string]string{}
	for _, node := range nodes {
		b, _ := json.Marshal(node)
		h := sha256.Sum256(b)
		id := hex.EncodeToString(h[:])
		ids = append(ids, id)
		names[node["name"].(string)] = id
	}
	return ids, names
}

// The core's typed target-delay 503/504 contract is a completed path failure;
// controller/auth/format failures are not. Ordinary 200..599 target responses
// are accepted by the delay probe and remain path evidence, not service health.
func independentNode(ctx context.Context, name, id, pool string, generation personalroute.Generation, probes []string, request func(context.Context, string, any) error) independentSample {
	started := time.Now()
	o := personalroute.Observation{CandidateID: id, PoolID: pool, Generation: generation, Scope: personalroute.IndependentHealth, Outcome: personalroute.Unknown, StartedAt: started}
	result := independentSample{Name: name, ID: id, Latency: -1}
	failed := 0
	unknown := false
	for _, target := range probes {
		begin := time.Now()
		var delay struct {
			Delay *int `json:"delay"`
		}
		q := url.Values{"url": {target}, "timeout": {"3000"}, "expected": {"200-599"}}
		if e := request(ctx, "/proxies/"+url.PathEscape(name)+"/delay?"+q.Encode(), &delay); e != nil {
			if ctx.Err() != nil {
				break
			}
			if delayTargetFailure(e) {
				failed++
			} else {
				unknown = true
			}
			continue
		}
		var details struct {
			Extra map[string]selector.ProbeState `json:"extra"`
		}
		if e := request(ctx, "/proxies/"+url.PathEscape(name), &details); e != nil {
			unknown = true
			continue
		}
		ms, known := selector.ObservedDelay(begin, time.Now(), delay.Delay, details.Extra[target])
		if !known {
			unknown = true
			continue
		}
		if ms >= 0 {
			o.Outcome = personalroute.Healthy
			result.Latency = ms
			break
		}
		failed++
	}
	if ctx.Err() != nil {
		o.Outcome = personalroute.Canceled
	} else if o.Outcome != personalroute.Healthy && len(probes) > 0 && failed == len(probes) && !unknown {
		o.Outcome = personalroute.PathFailed
	}
	o.FinishedAt = time.Now()
	result.Observation = o
	return result
}

// Independent checks have their own bounded background pool. One target cannot
// consume a node's entire batch deadline, and scheduling continues from the
// previous cursor instead of restarting at P001. The supported fallback budget
// is 256 distinct node/target checks: 32 workers * eight 4s slots = 32s, below
// the immutable 45s evidence age. Larger configurations are still fairly ranked
// but explicitly cannot authorize fallback. No freshness limit is widened.
const independentParallel = 32
const independentCoverageBudget = 256
const independentTargetLimit = 32

type independentJob struct{ node, target int }
type independentJobResult struct {
	job    independentJob
	sample independentSample
}
type independentScheduler struct {
	nodes                                 []policy.Node
	targets                               []string
	ids                                   []string
	pool                                  string
	generation                            personalroute.Generation
	scope                                 personalroute.Scope
	progress                              [][]independentSample
	jobs                                  []independentJob
	cursor                                int
	coverageReason                        string
	allTargets                            bool
	parallel, batchLimit                  int
	targetTimeout, cycleDelay, batchDelay time.Duration
}

func newIndependentScheduler(nodes []policy.Node, probes []string, generation personalroute.Generation, scope personalroute.Scope) *independentScheduler {
	ids, _ := candidateIDs(nodes)
	pool, _ := personalroute.PoolID(ids)
	s := &independentScheduler{nodes: nodes, ids: ids, pool: pool, generation: generation, scope: scope, allTargets: true,
		parallel: independentParallel, batchLimit: independentCoverageBudget, targetTimeout: 4 * time.Second, cycleDelay: 5 * time.Second, batchDelay: time.Second}
	seen := map[string]bool{}
	for _, target := range probes {
		if !seen[target] {
			seen[target] = true
			s.targets = append(s.targets, target)
		}
	}
	if len(s.targets) == 0 || scope != personalroute.IndependentHealth {
		s.coverageReason = "independent_health_not_configured"
	}
	if len(s.targets) > independentTargetLimit {
		// Keep ranking memory/work bounded. Untested targets cannot turn the
		// sampled subset into a confirmed node failure or a fallback proof.
		s.targets = s.targets[:independentTargetLimit]
		s.allTargets = false
		s.coverageReason = "independent_health_coverage_budget_exceeded"
	}
	if len(nodes)*len(s.targets) > independentCoverageBudget {
		s.coverageReason = "independent_health_coverage_budget_exceeded"
	}
	s.progress = make([][]independentSample, len(nodes))
	for n := range nodes {
		s.progress[n] = make([]independentSample, len(s.targets))
	}
	// Target-major ordering visits every node before a second URL can consume
	// the next slot. Even over-budget ranking therefore cannot starve the tail.
	for p := range s.targets {
		for n := range nodes {
			s.jobs = append(s.jobs, independentJob{n, p})
		}
	}
	return s
}

func (s *independentScheduler) snapshot(now time.Time) independentSweep {
	r := independentSweep{Generation: s.generation, Started: now, CoverageReason: s.coverageReason}
	for n, node := range s.nodes {
		v := independentSample{Name: node["name"].(string), ID: s.ids[n], Latency: -1}
		o := personalroute.Observation{CandidateID: v.ID, PoolID: s.pool, Generation: s.generation, Scope: s.scope, Outcome: personalroute.Unknown}
		failed, healthy := 0, false
		for _, target := range s.progress[n] {
			p := target.Observation
			if p.StartedAt.IsZero() || p.FinishedAt.IsZero() || p.StartedAt.After(now) || p.FinishedAt.After(now) || p.FinishedAt.Before(p.StartedAt) || now.Sub(p.StartedAt) >= personalroute.DefaultMaxAge || now.Sub(p.FinishedAt) >= personalroute.DefaultMaxAge {
				continue
			}
			if p.Outcome == personalroute.Healthy {
				if !healthy || target.Latency < v.Latency {
					o, v.Latency = p, target.Latency
				}
				healthy = true
			}
			if !healthy {
				if o.StartedAt.IsZero() || p.StartedAt.Before(o.StartedAt) {
					o.StartedAt = p.StartedAt
				}
				if p.FinishedAt.After(o.FinishedAt) {
					o.FinishedAt = p.FinishedAt
				}
			}
			if p.Outcome == personalroute.PathFailed {
				failed++
			}
		}
		if !healthy && failed == len(s.targets) && len(s.targets) != 0 && s.allTargets {
			o.Outcome = personalroute.PathFailed
		}
		v.Observation = o
		if !o.StartedAt.IsZero() && o.StartedAt.Before(r.Started) {
			r.Started = o.StartedAt
		}
		r.Samples = append(r.Samples, v)
	}
	return r
}

func publishIndependent(out chan independentSweep, value independentSweep) {
	// A slow GUI/core verification must not block health checks. Keep only the
	// newest complete snapshot; the owner compares per-node timestamps before
	// submitting ranking observations so old samples are not counted twice.
	select {
	case out <- value:
		return
	default:
	}
	select {
	case <-out:
	default:
	}
	select {
	case out <- value:
	default:
	}
}

func (s *independentScheduler) start(ctx context.Context, request func(context.Context, string, any) error) <-chan independentSweep {
	out := make(chan independentSweep, 1)
	go func() {
		defer close(out)
		publishIndependent(out, s.snapshot(time.Now()))
		if len(s.jobs) == 0 {
			<-ctx.Done()
			return
		}
		jobs := make(chan independentJob, s.batchLimit)
		results := make(chan independentJobResult, s.parallel)
		var workers sync.WaitGroup
		defer workers.Wait()
		defer close(jobs)
		for i := 0; i < s.parallel && i < len(s.jobs); i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for job := range jobs {
					if ctx.Err() != nil {
						return
					}
					work, cancel := context.WithTimeout(ctx, s.targetTimeout)
					v := independentNode(work, s.nodes[job.node]["name"].(string), s.ids[job.node], s.pool, s.generation, []string{s.targets[job.target]}, request)
					cancel()
					v.Observation.Scope = s.scope
					select {
					case results <- independentJobResult{job, v}:
					case <-ctx.Done():
						return
					}
				}
			}()
		}
		for ctx.Err() == nil {
			count := len(s.jobs)
			if count > s.batchLimit {
				count = s.batchLimit
			}
			for i := 0; i < count; i++ {
				job := s.jobs[s.cursor]
				s.cursor = (s.cursor + 1) % len(s.jobs)
				select {
				case jobs <- job:
				case <-ctx.Done():
					return
				}
			}
			for i := 0; i < count; i++ {
				select {
				case <-ctx.Done():
					return
				case r := <-results:
					s.progress[r.job.node][r.job.target] = r.sample
					publishIndependent(out, s.snapshot(time.Now()))
				}
			}
			delay := s.batchDelay
			if len(s.jobs) <= s.batchLimit {
				delay = s.cycleDelay
			}
			// Fast controller errors must not create an unbounded busy loop,
			// including when a large ranking-only pool exceeds proof coverage.
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return out
}

func fallbackDecisionWithCoverage(intent policy.ChannelIntent, nodes []policy.Node, g personalroute.Generation, samples []independentSample, now time.Time, reason string) personalroute.Decision {
	if intent.Personal && reason != "" {
		return personalroute.Decision{Reason: reason}
	}
	return fallbackDecision(intent, nodes, g, samples, now)
}
func fallbackDecision(intent policy.ChannelIntent, nodes []policy.Node, g personalroute.Generation, samples []independentSample, now time.Time) personalroute.Decision {
	ids, _ := candidateIDs(nodes)
	observations := make([]personalroute.Observation, 0, len(samples))
	for _, sample := range samples {
		observations = append(observations, sample.Observation)
	}
	return personalroute.Evaluate(personalroute.Input{ManualDisabled: !intent.Personal, Generation: g, Candidates: ids, Observations: observations, Now: now})
}
