// Package selector changes only the personal pool, never traffic authorization.
package selector

import "time"

const Reject = "REJECT"

type Options struct {
	AdvantageMS           int
	Confirmations         int
	MinHold, RecoveryHold time.Duration
	RecoverySuccesses     int
}

func Defaults() Options { return Options{150, 3, 60 * time.Second, 10 * time.Second, 2} }

type health struct {
	Successes int
	FailedAt  time.Time
	Observed  time.Time
	Latency   int
}
type Policy struct {
	Nodes         []string
	Options       Options
	Current       string
	LastSwitch    time.Time
	proposal      string
	confirmations int
	health        map[string]health
	cursor        int
}

func New(nodes []string) *Policy {
	return &Policy{Nodes: append([]string{}, nodes...), Options: Defaults(), Current: Reject, health: map[string]health{}}
}

// ReportFailure invalidates a node whose real request failed after its latency
// sample succeeded. The normal recovery hold also applies to these failures.
// The caller must separately commit any successfully applied group change.
func (p *Policy) ReportFailure(node string, now time.Time) {
	for _, n := range p.Nodes {
		if n == node {
			p.health[node] = health{FailedAt: now}
			return
		}
	}
}

// Negative latency denotes failure of all approved probes for this node.
// Commit is separate: failed API writes must not count as completed switches.
func (p *Policy) Decide(now time.Time, latency map[string]int) (string, string) {
	complete := make(map[string]int, len(p.Nodes))
	for _, n := range p.Nodes {
		ms, ok := latency[n]
		if !ok {
			ms = -1
		}
		complete[n] = ms
	}
	return p.DecideSamples(now, complete)
}

// DecideSamples treats omitted measurements as unknown. Earlier positive
// measurements expire; cancellation never manufactures a node failure.
func (p *Policy) DecideSamples(now time.Time, latency map[string]int) (string, string) {
	return p.DecideSamplesSince(now, now, latency)
}

// A round started before a newer real request failure cannot clear that failure.
func (p *Policy) DecideSamplesSince(now, started time.Time, latency map[string]int) (string, string) {
	filtered := make(map[string]int, len(latency))
	for n, ms := range latency {
		h := p.health[n]
		if !h.FailedAt.After(started) && !h.Observed.After(started) {
			filtered[n] = ms
		}
	}
	return p.decideSamples(now, filtered, nil)
}

// TimedSample carries one node's actual observation interval. Coalesced
// background results must not borrow another node's earlier start time.
type TimedSample struct {
	Latency               int
	StartedAt, FinishedAt time.Time
}

func (p *Policy) DecideTimedSamples(now time.Time, samples map[string]TimedSample) (string, string) {
	latency := make(map[string]int, len(samples))
	finished := make(map[string]time.Time, len(samples))
	for n, sample := range samples {
		h := p.health[n]
		if sample.StartedAt.IsZero() || sample.FinishedAt.IsZero() || sample.FinishedAt.Before(sample.StartedAt) || sample.StartedAt.After(now) || sample.FinishedAt.After(now) || now.Sub(sample.StartedAt) >= 45*time.Second || now.Sub(sample.FinishedAt) >= 45*time.Second {
			continue
		}
		if !h.FailedAt.After(sample.StartedAt) && !h.Observed.After(sample.StartedAt) && (h.Observed.IsZero() || sample.FinishedAt.After(h.Observed)) {
			latency[n], finished[n] = sample.Latency, sample.FinishedAt
		}
	}
	return p.decideSamples(now, latency, finished)
}

func (p *Policy) decideSamples(now time.Time, latency map[string]int, finished map[string]time.Time) (string, string) {
	best := ""
	bestMS := int(^uint(0) >> 1)
	for _, n := range p.Nodes {
		h := p.health[n]
		ms, measured := latency[n]
		if measured {
			observed := now
			if at, ok := finished[n]; ok {
				observed = at
			}
			h.Observed, h.Latency = observed, ms
			if ms < 0 {
				h.Successes = 0
				h.FailedAt = observed
			} else {
				h.Successes++
			}
			p.health[n] = h
		}
		ms = h.Latency
		fresh := !h.Observed.IsZero() && !now.Before(h.Observed) && now.Sub(h.Observed) < 45*time.Second
		eligible := fresh && ms >= 0 && (h.FailedAt.IsZero() || (h.Successes >= p.Options.RecoverySuccesses && now.Sub(h.FailedAt) >= p.Options.RecoveryHold))
		if eligible && ms < bestMS {
			best = n
			bestMS = ms
		}
	}
	if best == "" {
		p.proposal = ""
		p.confirmations = 0
		return Reject, "no_healthy_node"
	}
	current := p.health[p.Current]
	currentMS := current.Latency
	healthy := !current.Observed.IsZero() && !now.Before(current.Observed) && now.Sub(current.Observed) < 45*time.Second && (current.FailedAt.IsZero() || (current.Successes >= p.Options.RecoverySuccesses && now.Sub(current.FailedAt) >= p.Options.RecoveryHold))
	if p.Current == Reject || !healthy || currentMS < 0 {
		p.proposal = ""
		p.confirmations = 0
		return best, "initial_or_failed_node"
	}
	if now.Sub(p.LastSwitch) < p.Options.MinHold {
		return p.Current, "minimum_hold"
	}
	if best == p.Current || currentMS-bestMS < p.Options.AdvantageMS {
		p.proposal = ""
		p.confirmations = 0
		return p.Current, "no_clear_advantage"
	}
	if _, sampled := latency[best]; !sampled {
		return p.Current, "awaiting_candidate_sample"
	}
	if _, sampled := latency[p.Current]; !sampled {
		return p.Current, "awaiting_current_sample"
	}
	if p.proposal == best {
		p.confirmations++
	} else {
		p.proposal = best
		p.confirmations = 1
	}
	if p.confirmations >= p.Options.Confirmations {
		return best, "confirmed_advantage"
	}
	return p.Current, "confirming_advantage"
}
func (p *Policy) Commit(node string, now time.Time) {
	if node != p.Current {
		p.Current = node
		p.LastSwitch = now
	} else {
		return
	}
	p.proposal = ""
	p.confirmations = 0
}

// NextBatch always revisits the selected node and rotates other candidates.
func (p *Policy) NextBatch(limit int) []string {
	if limit < 1 || len(p.Nodes) == 0 {
		return nil
	}
	result := []string{}
	if p.Current != Reject {
		for _, n := range p.Nodes {
			if n == p.Current {
				result = append(result, n)
				break
			}
		}
	}
	if p.proposal != "" && p.proposal != p.Current && len(result) < limit {
		result = append(result, p.proposal)
	}
	for visited := 0; visited < len(p.Nodes) && len(result) < limit; visited++ {
		n := p.Nodes[p.cursor%len(p.Nodes)]
		p.cursor = (p.cursor + 1) % len(p.Nodes)
		if n != p.Current && n != p.proposal {
			result = append(result, n)
		}
	}
	return result
}
