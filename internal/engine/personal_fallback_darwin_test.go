//go:build darwin

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"netlaunch/internal/personalroute"
	"netlaunch/internal/policy"
	"netlaunch/internal/selector"
)

func TestDarwinAutomaticFallbackRequiresCurrentCompleteIndependentFailures(t *testing.T) {
	now := time.Now()
	s := personalChangeFixture(t, true)
	nodes := []policy.Node{{"name": "P001"}, {"name": "P002"}}
	ids, _ := candidateIDs(nodes)
	pool, err := personalroute.PoolID(ids)
	if err != nil {
		t.Fatal(err)
	}
	gen := personalroute.Generation{Run: "run", Network: "network", Probe: "probe"}
	health := darwinPersonalHealth{binding: darwinHealthScope(s, "wake"), gen: gen, latest: independentSweep{Generation: gen}}
	latest := []independentSample{}
	for i, id := range ids {
		latest = append(latest, independentSample{ID: id, Observation: personalroute.Observation{
			CandidateID: id, PoolID: pool, Generation: gen, Scope: personalroute.IndependentHealth,
			Outcome: personalroute.PathFailed, StartedAt: now.Add(-time.Duration(i+2) * time.Second), FinishedAt: now.Add(-time.Second),
		}})
	}
	health.latest.Samples = latest
	expiry := now.Add(personalroute.DefaultMaxAge - 3*time.Second)
	if found := health.directDeadline(s, "wake", nodes, now); !found.Equal(expiry) {
		t.Fatal("missing deadline for the oldest complete path proof", found, expiry)
	}
	if !health.directDeadline(s, "wake", nodes, expiry).IsZero() || !health.directDeadline(s, "other-wake", nodes, now).IsZero() {
		t.Fatal("expired or old wake evidence allowed direct")
	}
	newGeneration := s
	newGeneration.ChannelGeneration++
	if !health.directDeadline(newGeneration, "wake", nodes, now).IsZero() {
		t.Fatal("old intent generation allowed direct")
	}
	health.latest.Samples = latest[:1]
	if !health.directDeadline(s, "wake", nodes, now).IsZero() {
		t.Fatal("missing candidate allowed direct")
	}
	health.latest.Samples = latest
	for _, result := range []personalroute.Outcome{personalroute.Healthy, personalroute.Unknown, personalroute.Canceled, personalroute.ServiceFailed} {
		health.latest.Samples[1].Observation.Outcome = result
		if !health.directDeadline(s, "wake", nodes, now).IsZero() {
			t.Fatal("non-path failure allowed direct", result)
		}
	}
	health.latest.Samples[1].Observation.Outcome = personalroute.PathFailed
	health.latest.Samples[1].Observation.Scope = personalroute.TargetRequest
	if !health.directDeadline(s, "wake", nodes, now).IsZero() {
		t.Fatal("service-only scope allowed direct")
	}
}

func TestDarwinAutomaticFallbackPublishesWithoutChangingIntent(t *testing.T) {
	s := personalChangeFixture(t, true)
	s.VPN.Bootstrap = true
	want := currentIntent(s)
	allow := func(State) bool { return true }
	authorize := func(s State) error {
		if !s.DarwinAutoFallbackPending {
			return errors.New("lost transition")
		}
		return nil
	}
	s.DarwinPersonal.Pending = true
	if err := beginDarwinAutoFallback(&s, s, true, allow); !errors.Is(err, errDarwinFallbackDeferred) {
		t.Fatal("automatic fallback competed with a manual request", err)
	}
	s.DarwinPersonal.Pending = false
	for _, direct := range []bool{true, false} {
		before := s
		if err := beginDarwinAutoFallback(&s, before, direct, allow); err != nil {
			t.Fatal(err)
		}
		if s.PersonalFallback || s.Personal != selector.Reject {
			t.Fatal("a prepared fallback reported direct")
		}
		var calls []string
		selectGroup := func(_ context.Context, group, target string) error {
			calls = append(calls, group+"="+target)
			return nil
		}
		openLease := func(_ context.Context, cutoff time.Time) (time.Time, error) {
			calls = append(calls, "open personal fallback lease")
			return cutoff, nil
		}
		if err := publishDarwinAutoFallback(t.Context(), &s, direct, time.Now().Add(time.Minute), authorize, selectGroup, openLease); err != nil {
			t.Fatal(err)
		}
		expected := []string{"PHYSICAL=PHYSICAL-BOUND"}
		if direct {
			expected = append(expected, "open personal fallback lease")
		}
		if !reflect.DeepEqual(calls, expected) || s.PersonalFallback != direct ||
			s.ChannelGeneration != before.ChannelGeneration || s.AppliedGeneration != before.AppliedGeneration ||
			currentIntent(s) != want || !s.VPN.Bootstrap {
			t.Fatal("automatic transition modified unrelated state", calls, s.PersonalFallback)
		}
	}
}

func TestDarwinFallbackGrantCannotOutliveTheValidationRun(t *testing.T) {
	s := personalChangeFixture(t, true)
	s.DarwinAutoFallbackPending = true
	s.Manifest.Created = time.Now()
	s.Manifest.ValidationTimeout = time.Minute
	runDeadline := darwinRunDeadline(s.Manifest)
	proofDeadline := runDeadline.Add(time.Minute)
	err := publishDarwinAutoFallback(t.Context(), &s, true, proofDeadline, func(State) error { return nil }, func(ctx context.Context, _, _ string) error {
		deadline, ok := ctx.Deadline()
		if !ok || !deadline.Equal(runDeadline) {
			t.Fatalf("controller deadline = %v, want %v", deadline, runDeadline)
		}
		return nil
	}, func(_ context.Context, deadline time.Time) (time.Time, error) {
		return deadline, nil
	})
	if err != nil || s.PersonalFallbackUntil == nil || !s.PersonalFallbackUntil.Equal(runDeadline) {
		t.Fatalf("fallback publication did not honor run deadline, got %v: %v", s.PersonalFallbackUntil, err)
	}
	if !darwinFallbackCutoff(s, time.Time{}).IsZero() {
		t.Fatal("validation deadline created missing proof")
	}
}

func TestDarwinFallbackReadbackCannotKeepUsingExpiredEvidence(t *testing.T) {
	s := personalChangeFixture(t, true)
	s.DarwinAutoFallbackPending = true
	personalWrite := make(chan struct{}, 1)
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == personalFallbackLeasePath:
			_, _ = io.Copy(io.Discard, r.Body)
			personalWrite <- struct{}{}
			select {
			case <-r.Context().Done():
			case <-time.After(time.Second):
			}
		case r.Method == http.MethodPut && r.URL.Path == "/proxies/PHYSICAL":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/proxies/PHYSICAL":
			_, _ = w.Write([]byte(`{"now":"PHYSICAL-BOUND"}`))
		case r.Method == http.MethodGet && r.URL.Path == personalFallbackLeasePath:
			_, _ = w.Write([]byte(`{"revision":"current","now_ms":10,"active":false}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer controller.Close()
	address := strings.TrimPrefix(controller.URL, "http://")
	until := time.Now().Add(300 * time.Millisecond)
	err := publishDarwinAutoFallback(t.Context(), &s, true, until, func(State) error { return nil }, func(ctx context.Context, group, target string) error {
		d, ok := ctx.Deadline()
		if !ok || !d.Equal(until) {
			t.Fatalf("controller I/O deadline = %v, want %v", d, until)
		}
		path := "/proxies/" + group
		if err := coreRequest(ctx, address, "test-secret", http.MethodPut, path, map[string]string{"name": target}, nil); err != nil {
			return err
		}
		var readback struct{ Now string }
		return coreRequest(ctx, address, "test-secret", http.MethodGet, path, nil, &readback)
	}, func(ctx context.Context, cutoff time.Time) (time.Time, error) {
		return setFallbackLease(ctx, openFallbackLease, cutoff, func(work context.Context, method string, in, out any) error {
			return coreRequest(work, address, "test-secret", method, personalFallbackLeasePath, in, out)
		})
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled readback returned %v", err)
	}
	select {
	case <-personalWrite:
	default:
		t.Fatal("the controller did not accept the write before its readback stalled")
	}
	if s.PersonalFallback || s.PersonalFallbackUntil != nil || !s.DarwinAutoFallbackPending {
		t.Fatal("a timed-out readback published fallback evidence")
	}
}

func TestDarwinFallbackExpiryDrainsOnlyPersonalPhysicalConnections(t *testing.T) {
	var calls []string
	err := drainDarwinFallbackConnections(func(method, path string, _, out any) error {
		calls = append(calls, method+" "+path)
		if out == nil {
			return nil
		}
		return json.Unmarshal([]byte(`{"connections":[{"id":"personal","chains":["PHYSICAL-BOUND","PHYSICAL","PERSONAL"]},{"id":"local","chains":["PHYSICAL-BOUND","PHYSICAL"]},{"id":"company","chains":["CORP-BOUND","CORP"]}]}`), out)
	})
	if err != nil || !reflect.DeepEqual(calls, []string{"GET /connections", "DELETE /connections/personal"}) {
		t.Fatal(calls, err)
	}
	now := time.Now()
	deadline := now.Add(time.Second)
	state := personalChangeFixture(t, true)
	state.Personal, state.PersonalFallback, state.PersonalFallbackUntil = "PHYSICAL", true, &deadline
	if darwinFallbackExpired(state, now) || !darwinFallbackExpired(state, deadline) {
		t.Fatal("hard fallback expiry moved its boundary")
	}
	report := publicStatus(state, now)
	if !report.PersonalFallback || RefreshStatus(report, deadline).PersonalFallback ||
		RefreshStatus(report, deadline).Channels["personal"].Reason != "check_expired" {
		t.Fatal("saved fallback evidence outlived its actual deadline")
	}
	state.Personal = selector.Reject
	if publicStatus(state, deadline).PersonalFallback || channelView(state, "personal", deadline).Reason == "all_candidates_failed" {
		t.Fatal("closed expiry continued to report an active direct route")
	}
}
