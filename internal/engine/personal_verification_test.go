//go:build darwin || windows

package engine

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"netlaunch/internal/policy"
)

func TestPersonalVerificationCoversAcceptedProbeList(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		count, wantSlices, wantParallel int
		budget, delay                   time.Duration
	}{
		{"small-list-selects-early", 5, 2, 4, time.Second, 0},
		// Scale the 18-second mixed budget and a successful 4.6-second
		// response by the same factor: three waves fit, four exceed it.
		{"thirteen-slow-probes-fit-the-budget", 13, 3, 5, 450 * time.Millisecond, 115 * time.Millisecond},
		{"large-list-keeps-bounded-parallelism", 49, 4, 16, time.Second, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := policy.Config{
				Version: 1, Ports: policy.Ports{Proxy: 7890, DNS: 9053},
				Personal:  policy.Channel{Domains: []string{"personal.example"}, DNS: []string{"https://192.0.2.2/dns-query"}},
				DirectDNS: []string{"192.0.2.3"},
				Probes:    []policy.Probe{{Channel: "direct", URL: "https://direct.example/"}},
			}
			for i := range tc.count {
				config.Probes = append(config.Probes, policy.Probe{Channel: "personal", URL: fmt.Sprintf("https://personal.example/check/%d", i)})
			}
			if err := config.ValidateForIntent(policy.ChannelIntent{Personal: true}); err != nil {
				t.Fatalf("test fixture is not accepted as a runtime policy: %v", err)
			}
			probes := personalTargets(config)
			for _, ingress := range []string{candidateListener, "mixed_ingress"} {
				t.Run(ingress, func(t *testing.T) {
					schedule := newProbeScheduleWithCapacity(personalVerificationParallelLimit)
					schedule.bindPersonalVerification(probeScope{node: "P001"}, probes)
					if schedule.parallel != tc.wantParallel {
						t.Fatalf("unexpected worker limit: %d", schedule.parallel)
					}
					var checked atomic.Int32
					ctx, cancel := context.WithTimeout(t.Context(), tc.budget)
					defer cancel()
					for i := 1; i <= schedule.personalVerificationSliceLimit(); i++ {
						if err := schedule.advance(ctx, func(work context.Context, _ policy.Probe) error {
							if tc.delay != 0 {
								wait := time.NewTimer(tc.delay)
								defer wait.Stop()
								select {
								case <-work.Done():
									return work.Err()
								case <-wait.C:
								}
							}
							checked.Add(1)
							return nil
						}); err != nil {
							t.Fatal(err)
						}
						status, failure := schedule.aggregate("personal", ingress, time.Now())
						if failure != nil {
							t.Fatal(failure)
						}
						if status.State == "ready" {
							if int(checked.Load()) != tc.count || i != tc.wantSlices || status.ProbeScope != ingress {
								t.Fatalf("ready on the wrong coverage: %d checks, %d slices, scope %s", checked.Load(), i, status.ProbeScope)
							}
							return
						}
					}
					t.Fatalf("verification ended after checking %d of %d required probes", checked.Load(), tc.count)
				})
			}
		})
	}
}
