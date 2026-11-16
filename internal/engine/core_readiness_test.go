//go:build darwin || windows

package engine

import (
	"context"
	"net/http"
	"reflect"
	"testing"
	"time"

	"netlaunch/internal/policy"
	"netlaunch/internal/selector"
)

type selectionProbeTransport func(*http.Request) (*http.Response, error)

func (f selectionProbeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPersonalSelectionTriesAnotherNodeAfterServiceRejection(t *testing.T) {
	for _, mode := range []string{"batch", "timed"} {
		t.Run(mode, func(t *testing.T) {
			const fast, working = "fast-denied", "slower-working"
			p := selector.New([]string{fast, working})
			state := State{Personal: selector.Reject}
			selected := selector.Reject
			var switches, verified []string
			selectNode := func(_ context.Context, node string) error {
				switches = append(switches, node)
				selected = node
				return nil
			}
			client := &http.Client{Transport: selectionProbeTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodHead || r.URL.Host != "service.example" || r.URL.Path != "/health" {
					t.Errorf("unapproved probe request: %s %s", r.Method, r.URL)
				}
				verified = append(verified, selected)
				code := http.StatusNoContent
				if selected != working {
					code = http.StatusForbidden
				}
				return &http.Response{StatusCode: code, Body: http.NoBody}, nil
			})}
			verify := func(ctx context.Context) error {
				return verifyPersonalSelection(ctx, client, []policy.Probe{{Channel: "personal", Purpose: "service", URL: "https://service.example/health"}})
			}
			updateState := func(fn func(*State) error) error { return fn(&state) }
			apply := func() {
				started := time.Now()
				decide := func(now time.Time) (string, string) {
					if mode == "timed" {
						return p.DecideTimedSamples(now, map[string]selector.TimedSample{
							fast:    {Latency: 20, StartedAt: started, FinishedAt: now},
							working: {Latency: 100, StartedAt: started, FinishedAt: now},
						})
					}
					return p.DecideSamplesSince(now, started, map[string]int{fast: 20, working: 100})
				}
				if err := applyPersonalChoice(t.Context(), p, decide, selectNode, verify, updateState); err != nil {
					t.Fatal(err)
				}
			}
			apply()
			h := state.Channels["personal"]
			if state.Personal != selector.Reject || state.PersonalFallback || h.Reason != "http_status_rejected" || h.ProbeScope != "mixed_ingress" || h.PathState != "verified" || h.ServiceState != "failed" {
				t.Fatalf("HTTP refusal did not close personal ingress with scoped service evidence: %+v", h)
			}
			apply()
			if p.Current != working || selected != working || state.Personal != working || state.PersonalFallback ||
				!reflect.DeepEqual(switches, []string{fast, selector.Reject, working}) || !reflect.DeepEqual(verified, []string{fast, working}) {
				t.Fatalf("fresh path latency starved the working node: current=%s switches=%v verified=%v", p.Current, switches, verified)
			}
		})
	}
}
