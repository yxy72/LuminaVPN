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
		name              string
		count, wantSlices int
	}{
		{"small-list-selects-early", 5, 2},
		{"thirteen-probes-reach-the-tail", 13, 4},
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
					schedule := newProbeSchedule()
					schedule.bind(probeScope{node: "P001"}, probes)
					var checked atomic.Int32
					ctx, cancel := context.WithTimeout(t.Context(), time.Second)
					defer cancel()
					for i := 1; i <= schedule.personalVerificationSliceLimit(); i++ {
						if err := schedule.advance(ctx, func(context.Context, policy.Probe) error {
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
