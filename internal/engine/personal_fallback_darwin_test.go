//go:build darwin

package engine

import (
	"encoding/json"
	"errors"
	"reflect"
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
		selectGroup := func(group, target string) error {
			calls = append(calls, group+"="+target)
			return nil
		}
		if err := publishDarwinAutoFallback(&s, direct, authorize, selectGroup); err != nil {
			t.Fatal(err)
		}
		expected := []string{"PHYSICAL=PHYSICAL-BOUND"}
		if direct {
			expected = append(expected, "PERSONAL=PHYSICAL")
		}
		if !reflect.DeepEqual(calls, expected) || s.PersonalFallback != direct ||
			s.ChannelGeneration != before.ChannelGeneration || s.AppliedGeneration != before.AppliedGeneration ||
			currentIntent(s) != want || !s.VPN.Bootstrap {
			t.Fatal("automatic transition modified unrelated state", calls, s.PersonalFallback)
		}
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
	state.Personal, state.PersonalFallback, state.DarwinAutoFallbackUntil = "PHYSICAL", true, &deadline
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
