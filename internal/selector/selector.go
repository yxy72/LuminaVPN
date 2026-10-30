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
}
type Policy struct {
	Nodes         []string
	Options       Options
	Current       string
	LastSwitch    time.Time
	proposal      string
	confirmations int
	health        map[string]health
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
	best := ""
	bestMS := int(^uint(0) >> 1)
	for _, n := range p.Nodes {
		h := p.health[n]
		ms, exists := latency[n]
		if !exists || ms < 0 {
			h.Successes = 0
			h.FailedAt = now
		} else {
			h.Successes++
		}
		p.health[n] = h
		eligible := exists && ms >= 0 && (h.FailedAt.IsZero() || (h.Successes >= p.Options.RecoverySuccesses && now.Sub(h.FailedAt) >= p.Options.RecoveryHold))
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
	currentMS, healthy := latency[p.Current]
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
