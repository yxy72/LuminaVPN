//go:build darwin || windows

package engine

import (
	"testing"
	"time"

	"netlaunch/internal/policy"
	"netlaunch/internal/selector"
)

func TestCandidateRefusalAndIncompleteProbeYieldToWorkingAlternative(t *testing.T) {
	for _, scenario := range []struct {
		name string
		err  error
	}{{"service refusal", checkProbeStatus(policy.Probe{Channel: "personal", Purpose: "service"}, 403)}, {"incomplete", nil}} {
		t.Run(scenario.name, func(t *testing.T) {
			const fast, working, incumbent = "fast-denied", "slower-working", "healthy-incumbent"
			p := selector.New([]string{fast, working, incumbent})
			p.Options.MinHold, p.Options.Confirmations = 0, 1
			now := time.Now()
			p.Commit(incumbent, now.Add(-time.Second))
			latency := map[string]int{fast: 20, working: 300, incumbent: 800}
			node, _ := p.DecideSamples(now, latency)
			if node != fast {
				t.Fatalf("first node = %q", node)
			}
			notePersonalProbeFailure(p, node, scenario.err)
			node, _ = p.DecideSamples(time.Now(), latency)
			if node != working || p.Current != incumbent {
				t.Fatalf("verification starved the alternative or changed the incumbent: %q, %q", node, p.Current)
			}
		})
	}
}
