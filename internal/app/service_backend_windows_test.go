//go:build windows

package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"netlaunch/internal/engine"
	"netlaunch/internal/policy"
	p "netlaunch/internal/serviceprotocol"
	"netlaunch/internal/winservice"
)

func backendFixtureBinding() winservice.Binding {
	return winservice.Binding{ProfileID: "profile", OwnerSID: "S-1-5-21-1", LogonSID: "S-1-5-5-1-1", AuthenticationID: "auth", SessionID: 1, ExecutorSID: "S-1-5-18", ServiceInstance: "instance", Revision: 1, RunRef: "run-ref", PreparedRunID: "netlaunch-" + strings.Repeat("a", 32), SpecDigest: strings.Repeat("b", 64), Mode: "daily"}
}
func fixtureRecoveryProof() engine.ServiceRecoveryProof {
	now := time.Now()
	return engine.ServiceRecoveryProof{Clean: true, IdentityMappingComplete: true, AdaptersAbsent: true, ProcessesGone: true, NetworkRestored: true, WFPAbsent: true, IPv6Absent: true, StartedAt: now, FinishedAt: now}
}

type fixtureRestorations struct{ saved bool }

func (f *fixtureRestorations) Save(winservice.Binding, string, json.RawMessage) (string, error) {
	f.saved = true
	return "restore-fixture", nil
}
func (f *fixtureRestorations) Verify(winservice.Binding) (bool, error) { return f.saved, nil }

func TestServiceBackendRequiresCompleteAppliedGenerationAndIntent(t *testing.T) {
	intent := policy.ChannelIntent{Company: true, Personal: false, Environment: "office"}
	status := engine.Status{TakeoverActive: true, ChannelGeneration: 2, AppliedGeneration: 2, DesiredChannels: &intent, AppliedChannels: &intent, Phase: "managed"}
	if !sameAppliedIntent(status, intent) {
		t.Fatal("managed actual intent was not acknowledged")
	}
	for _, alter := range []func(*engine.Status){func(s *engine.Status) { s.TakeoverActive = false }, func(s *engine.Status) { s.AppliedGeneration = 1 }, func(s *engine.Status) { s.ChannelGeneration = 0; s.AppliedGeneration = 0 }, func(s *engine.Status) { s.AppliedChannels = nil }, func(s *engine.Status) { s.Phase = "stopped" }, func(s *engine.Status) { other := intent; other.Company = false; s.AppliedChannels = &other }} {
		bad := status
		alter(&bad)
		if sameAppliedIntent(bad, intent) {
			t.Fatal("unapplied/inactive intent became a successful operation")
		}
	}
}
func TestServiceBackendLateReadbackCannotPassApplyDeadline(t *testing.T) {
	now := time.Now()
	intent := policy.ChannelIntent{Environment: "home"}
	binding := backendFixtureBinding()
	backend := fixedLifecycleBackend{deps: serviceBackendDependencies{now: func() time.Time { return now }, lifecycle: func(ctx context.Context, _ winservice.LifecycleAction, _ []byte) ([]byte, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("helper call missing absolute transition bound")
		}
		now = now.Add(61 * time.Second)
		return json.Marshal(engine.ServiceStatusResult{RunID: binding.PreparedRunID, Status: engine.Status{TakeoverActive: true, Phase: "managed", ChannelGeneration: 1, AppliedGeneration: 1, DesiredChannels: &intent, AppliedChannels: &intent}})
	}}}
	if _, err := backend.awaitApplied(context.Background(), binding, intent); err == nil {
		t.Fatal("late successful helper read became an in-deadline pass")
	}
}
func TestRecoveryProofRequiresEveryResourceAndNoReadErrors(t *testing.T) {
	proof := fixtureRecoveryProof()
	if !completeRecoveryProof(proof) {
		t.Fatal("complete fixture rejected")
	}
	for _, alter := range []func(*engine.ServiceRecoveryProof){func(p *engine.ServiceRecoveryProof) { p.Clean = false }, func(p *engine.ServiceRecoveryProof) { p.IdentityMappingComplete = false }, func(p *engine.ServiceRecoveryProof) { p.AdaptersAbsent = false }, func(p *engine.ServiceRecoveryProof) { p.ProcessesGone = false }, func(p *engine.ServiceRecoveryProof) { p.NetworkRestored = false }, func(p *engine.ServiceRecoveryProof) { p.WFPAbsent = false }, func(p *engine.ServiceRecoveryProof) { p.IPv6Absent = false }, func(p *engine.ServiceRecoveryProof) { p.Errors = []string{"unknown"} }, func(p *engine.ServiceRecoveryProof) { p.StartedAt = time.Time{} }} {
		bad := proof
		alter(&bad)
		if completeRecoveryProof(bad) {
			t.Fatal("incomplete cleanup became restored")
		}
	}
}
func TestServiceSnapshotProjectsOnlySafeActualEvidence(t *testing.T) {
	result := engine.ServiceStatusResult{IPv6State: "unknown", Status: engine.Status{Phase: "managed", TakeoverActive: true, Personal: "private-node-secret", Error: "private-cookie", Channels: map[string]engine.ChannelStatus{"company": {State: "ready", PathState: "verified", ProbeScope: "explicit_proxy", Reason: "private.example.invalid"}, "personal": {State: "degraded", PathState: "physical_direct", Reason: "all_candidates_failed"}}, PersonalFallback: true}}
	company := projectServiceChannel(result, "company", true)
	personal := projectServiceChannel(result, "personal", true)
	if company.Route == "vpn" || company.IPv6 == "blocked" || company.Reason == "private.example.invalid" {
		t.Fatal("configured policy/proxy evidence was promoted to actual system routing")
	}
	if personal.Route != "direct" || personal.Health != nil || personal.Reason == "all_candidates_failed" {
		t.Fatal("fallback exposed an unsupported full-set health claim")
	}
	raw, _ := json.Marshal([]p.Channel{company, personal})
	if strings.Contains(string(raw), "private") {
		t.Fatal("private runtime values escaped projection")
	}
	result.IPv6State = "blocked"
	result.IPv6Blocked = true
	result.IPv6CheckedAt = time.Now()
	result.Status.Channels["company"] = engine.ChannelStatus{State: "ready", PathState: "verified", ProbeScope: "system_tun"}
	if got := projectServiceChannel(result, "company", true); got.Route != "vpn" || got.IPv6 != "blocked" {
		t.Fatal("actual verified evidence omitted")
	}
}

func TestBackendRecoveryUsesCurrentDurableIdentityAndStrictProof(t *testing.T) {
	binding := backendFixtureBinding()
	old := binding
	old.PreparedRunID = ""
	old.SpecDigest = ""
	store := &winservice.MemoryStore{Bindings: map[string]winservice.Binding{"profile": binding}}
	for _, clean := range []bool{false, true} {
		t.Run(map[bool]string{false: "incomplete", true: "strict"}[clean], func(t *testing.T) {
			backend := fixedLifecycleBackend{owners: store, deps: serviceBackendDependencies{restorations: &fixtureRestorations{}, now: time.Now, lifecycle: func(_ context.Context, action winservice.LifecycleAction, input []byte) ([]byte, error) {
				if action != winservice.RecoverLifecycle {
					t.Fatal("unexpected helper action")
				}
				var payload ServiceRunPayload
				if decodeServiceHelperJSON(input, &payload) != nil || payload.RunID != binding.PreparedRunID || payload.SpecDigest != binding.SpecDigest {
					t.Fatal("recovery used stale pre-prepare binding")
				}
				proof := fixtureRecoveryProof()
				proof.AdaptersAbsent = clean
				return json.Marshal(struct {
					RunID string                      `json:"run_id"`
					Clean bool                        `json:"clean"`
					Proof engine.ServiceRecoveryProof `json:"proof"`
				}{binding.PreparedRunID, true, proof})
			}}}
			completion, err := backend.restoreOwned(context.Background(), old, func(winservice.Progress) {})
			if clean && (err != nil || !completion.Restored) {
				t.Fatal("strict recovery not acknowledged")
			}
			if !clean && (err == nil || completion.Restored) {
				t.Fatal("incomplete recovery acknowledged")
			}
		})
	}
}
func TestPristineInstalledExitNeedsIndependentEmptyStateProof(t *testing.T) {
	binding := backendFixtureBinding()
	binding.RunRef = ""
	binding.PreparedRunID = ""
	binding.SpecDigest = ""
	binding.Mode = ""
	store := &winservice.MemoryStore{Bindings: map[string]winservice.Binding{"profile": binding}}
	for _, proved := range []bool{false, true} {
		backend := fixedLifecycleBackend{owners: store, deps: serviceBackendDependencies{restorations: &fixtureRestorations{}, now: time.Now, pristine: func(winservice.Binding) (bool, error) {
			if !proved {
				return false, errors.New("unknown historical entry")
			}
			return true, nil
		}}}
		completion, err := backend.restoreOwned(context.Background(), binding, func(winservice.Progress) {})
		if proved && (err != nil || !completion.Restored) {
			t.Fatal("fresh verified empty service could not exit")
		}
		if !proved && (err == nil || completion.Restored) {
			t.Fatal("idle label substituted for owned-state proof")
		}
	}
}
func TestProductionAuthGateDoesNotLaunchUnboundNetworkWorker(t *testing.T) {
	backend := fixedLifecycleBackend{}
	if err := backend.authenticate(context.Background(), winservice.VerifiedPrincipal{}, backendFixtureBinding(), policy.ChannelIntent{}, policy.Config{}, func(winservice.Progress) {}); err == nil {
		t.Fatal("missing physical authorization launched authentication")
	}
}
func TestPublishedRestorationLetsRestartedIdleServiceQuitWithoutDeletingHistory(t *testing.T) {
	binding := backendFixtureBinding()
	binding.RunRef = ""
	binding.PreparedRunID = ""
	binding.SpecDigest = ""
	binding.Mode = ""
	binding.LastRestorationID = "restore-fixture"
	store := &winservice.MemoryStore{Bindings: map[string]winservice.Binding{"profile": binding}}
	restarted := fixedLifecycleBackend{owners: store, deps: serviceBackendDependencies{restorations: &fixtureRestorations{saved: true}, pristine: func(winservice.Binding) (bool, error) {
		t.Fatal("historical directories must not be deleted or required pristine after published strict restore")
		return false, nil
	}}}
	completion, err := restarted.restoreOwned(context.Background(), binding, func(winservice.Progress) {})
	if err != nil || !completion.Restored || completion.RestorationID != binding.LastRestorationID {
		t.Fatal("durable same-generation proof did not permit idle quit")
	}
}
func TestUnpreparedFailureCanRecoverOnlyWithNeverPublishedCensusProof(t *testing.T) {
	binding := backendFixtureBinding()
	binding.PreparedRunID = ""
	binding.SpecDigest = ""
	store := &winservice.MemoryStore{Bindings: map[string]winservice.Binding{"profile": binding}}
	for _, complete := range []bool{false, true} {
		backend := fixedLifecycleBackend{owners: store, deps: serviceBackendDependencies{restorations: &fixtureRestorations{}, lifecycle: func(_ context.Context, action winservice.LifecycleAction, input []byte) ([]byte, error) {
			if action != winservice.AbortPrepareLifecycle {
				t.Fatal("unprepared recovery chose regular run/down")
			}
			var ref struct {
				ProfileID string `json:"profile_id"`
				RunRef    string `json:"binding_run_ref"`
				Instance  string `json:"service_instance"`
			}
			if decodeServiceHelperJSON(input, &ref) != nil || ref.RunRef != binding.RunRef || ref.Instance != binding.ServiceInstance {
				t.Fatal("abort omitted exact service claim")
			}
			now := time.Now()
			return json.Marshal(map[string]any{"run_ref": binding.RunRef, "clean": true, "proof": map[string]any{"clean": true, "never_bound": true, "identity_census_complete": complete, "never_served": true, "prepared_only": true, "retained_run_ids": []string{}, "errors": []string{}, "started_at": now, "finished_at": now}})
		}}}
		result, err := backend.restoreOwned(context.Background(), binding, func(winservice.Progress) {})
		if complete && (err != nil || !result.Restored) {
			t.Fatal("exact unpublished census did not recover")
		}
		if !complete && (err == nil || result.Restored) {
			t.Fatal("partial/unknown prepare was blindly cleared")
		}
	}
}

type stopFixturePreferences struct{ saves int }

func (f *stopFixturePreferences) Load() (p.SettingsPayload, error) {
	return p.SettingsPayload{Environment: "home"}, nil
}
func (f *stopFixturePreferences) Save(p.SettingsPayload) error { f.saves++; return nil }

func stoppedBackendFixture(t *testing.T, strict bool) (*fixedLifecycleBackend, *winservice.MemoryStore, winservice.Binding, *stopFixturePreferences, *int) {
	t.Helper()
	raw, err := os.ReadFile("../../examples/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(ServiceUserSnapshotData{Policy: cfg, SavedPolicy: cfg, PolicyRevision: strings.Repeat("c", 64), EffectiveDigest: strings.Repeat("d", 64)})
	if err != nil {
		t.Fatal(err)
	}
	binding := backendFixtureBinding()
	store := &winservice.MemoryStore{Bindings: map[string]winservice.Binding{"profile": binding}}
	prefs := &stopFixturePreferences{}
	reads := new(int)
	backend := &fixedLifecycleBackend{owners: store, deps: serviceBackendDependencies{
		now: time.Now, prefs: prefs, restorations: &fixtureRestorations{},
		snapshot: func(context.Context, winservice.VerifiedPrincipal, winservice.Binding) ([]byte, error) {
			*reads++
			return append([]byte(nil), data...), nil
		},
		workspace: func(context.Context, winservice.VerifiedPrincipal, winservice.Binding, p.WorkspacePayload) ([]byte, error) {
			return []byte(`{"completed":true,"result":{}}`), nil
		},
		lifecycle: func(context.Context, winservice.LifecycleAction, []byte) ([]byte, error) {
			proof := fixtureRecoveryProof()
			proof.NetworkRestored = strict
			return json.Marshal(map[string]any{"run_id": binding.PreparedRunID, "clean": true, "proof": proof})
		},
	}}
	return backend, store, binding, prefs, reads
}

func publishStoppedFixture(t *testing.T, store *winservice.MemoryStore, binding winservice.Binding, completion winservice.Completion) winservice.Binding {
	t.Helper()
	binding.RunRef, binding.PreparedRunID, binding.SpecDigest, binding.Mode = "", "", "", ""
	binding.LastRestorationID, binding.Revision = completion.RestorationID, completion.Revision
	if err := store.Save(binding); err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestSuccessfulOrdinaryStopReopensWorkspaceSettingsAndSnapshot(t *testing.T) {
	backend, store, binding, prefs, reads := stoppedBackendFixture(t, true)
	completion, err := backend.restoreOwned(context.Background(), binding, func(winservice.Progress) {})
	if err != nil || !completion.Restored {
		t.Fatal("strict stop failed", err)
	}
	idle := publishStoppedFixture(t, store, binding, completion)
	if _, err = backend.Workspace(context.Background(), winservice.VerifiedPrincipal{}, idle, p.WorkspacePayload{Action: "import_nodes"}, func(winservice.Progress) {}); err != nil {
		t.Fatal("successful stop permanently blocked workspace", err)
	}
	if _, err = backend.applySettings(context.Background(), winservice.VerifiedPrincipal{}, idle, p.SettingsPayload{Environment: "office"}, func(winservice.Progress) {}); err != nil || prefs.saves != 1 {
		t.Fatal("successful stop permanently blocked saved settings", err)
	}
	snapshot, err := backend.SnapshotForCaller(context.Background(), winservice.VerifiedPrincipal{}, idle)
	if err != nil || !snapshot.Restored || snapshot.ServiceState != "available" || *reads != 2 {
		t.Fatal("successful stop did not permit fresh user inventory and restored snapshot", err)
	}
}

func TestFailedOrdinaryStopKeepsUserWorkersClosed(t *testing.T) {
	backend, _, binding, _, reads := stoppedBackendFixture(t, false)
	completion, err := backend.restoreOwned(context.Background(), binding, func(winservice.Progress) {})
	if err == nil || completion.Restored {
		t.Fatal("partial restoration acknowledged")
	}
	if _, err = backend.userSnapshot(context.Background(), winservice.VerifiedPrincipal{}, binding); err == nil || *reads != 0 {
		t.Fatal("failed restoration reopened user worker")
	}
	backend.broker = &winservice.Broker{}
	if _, err = backend.start(context.Background(), winservice.AuthorizedOperation{}, binding, func(winservice.Progress) {}); err == nil || *reads != 0 {
		t.Fatal("start cleared an unresolved recovery barrier")
	}
}

func TestSCMSealSurvivesStrictRecoveryAndLateStart(t *testing.T) {
	backend, store, binding, _, reads := stoppedBackendFixture(t, true)
	backend.SealForShutdown()
	completion, err := backend.restoreOwned(context.Background(), binding, func(winservice.Progress) {})
	if err != nil || !completion.Restored {
		t.Fatal("SCM recovery failed", err)
	}
	idle := publishStoppedFixture(t, store, binding, completion)
	if _, err = backend.userSnapshot(context.Background(), winservice.VerifiedPrincipal{}, idle); err == nil || *reads != 0 {
		t.Fatal("SCM seal reopened snapshot worker")
	}
	if _, err = backend.Workspace(context.Background(), winservice.VerifiedPrincipal{}, idle, p.WorkspacePayload{Action: "import_nodes"}, func(winservice.Progress) {}); err == nil {
		t.Fatal("SCM seal reopened workspace")
	}
	backend.broker = &winservice.Broker{}
	if _, err = backend.start(context.Background(), winservice.AuthorizedOperation{}, idle, func(winservice.Progress) {}); err == nil || *reads != 0 {
		t.Fatal("late start undid SCM shutdown")
	}
}

func TestOrdinaryStopWaitsForExistingUserWorkerBeforeReopening(t *testing.T) {
	backend, _, binding, _, _ := stoppedBackendFixture(t, true)
	entered, release := make(chan struct{}), make(chan struct{})
	read := backend.deps.snapshot
	backend.deps.snapshot = func(ctx context.Context, v winservice.VerifiedPrincipal, b winservice.Binding) ([]byte, error) {
		close(entered)
		<-release
		return read(ctx, v, b)
	}
	worker := make(chan error, 1)
	go func() {
		_, err := backend.userSnapshot(context.Background(), winservice.VerifiedPrincipal{}, binding)
		worker <- err
	}()
	<-entered
	stopped := make(chan error, 1)
	go func() {
		_, err := backend.restoreOwned(context.Background(), binding, func(winservice.Progress) {})
		stopped <- err
	}()
	until := time.Now().Add(time.Second)
	for {
		backend.mu.Lock()
		closed := backend.exiting
		backend.mu.Unlock()
		if closed {
			break
		}
		if time.Now().After(until) {
			t.Fatal("stop barrier not entered")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-stopped:
		t.Fatal("stop acknowledged before old worker exited")
	default:
	}
	if _, err := backend.userSnapshot(context.Background(), winservice.VerifiedPrincipal{}, binding); err == nil {
		t.Fatal("another user worker crossed stop barrier")
	}
	close(release)
	if err := <-worker; err != nil {
		t.Fatal(err)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	closed := backend.barrierClosedLocked()
	backend.mu.Unlock()
	if closed {
		t.Fatal("confirmed old-worker exit did not reopen ordinary work")
	}
}

func TestCleanNativeRecoveryCannotReplaceUserWorkerExitProof(t *testing.T) {
	backend, _, binding, _, reads := stoppedBackendFixture(t, true)
	backend.workers = 1
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	completion, err := backend.restoreOwned(ctx, binding, func(winservice.Progress) {})
	if err == nil || completion.Restored {
		t.Fatal("clean native proof replaced an unconfirmed user worker exit")
	}
	if _, err := backend.userSnapshot(context.Background(), winservice.VerifiedPrincipal{}, binding); err == nil || *reads != 0 {
		t.Fatal("worker-exit timeout reopened user work")
	}
}

func TestSCMSealDuringOrdinaryRecoverySurvivesLateSuccess(t *testing.T) {
	backend, _, binding, _, _ := stoppedBackendFixture(t, true)
	entered, release := make(chan struct{}), make(chan struct{})
	recover := backend.deps.lifecycle
	backend.deps.lifecycle = func(ctx context.Context, action winservice.LifecycleAction, input []byte) ([]byte, error) {
		close(entered)
		<-release
		return recover(ctx, action, input)
	}
	done := make(chan error, 1)
	go func() {
		_, err := backend.restoreOwned(context.Background(), binding, func(winservice.Progress) {})
		done <- err
	}()
	<-entered
	backend.SealForShutdown()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	closed, sealed := backend.barrierClosedLocked(), backend.sealed
	backend.mu.Unlock()
	if !closed || !sealed {
		t.Fatal("late successful ordinary stop cleared an SCM shutdown seal")
	}
}

func TestEnrollmentPublicationCanFinishWithoutReopeningSCMSeal(t *testing.T) {
	for _, sealed := range []bool{false, true} {
		backend := &fixedLifecycleBackend{exiting: true, enrollmentBarrier: true, enrollmentFailure: true}
		if sealed {
			backend.SealForShutdown()
		}
		prefs, restorations := &stopFixturePreferences{}, &fixtureRestorations{saved: true}
		if err := backend.finishEnrollmentRotation(prefs, restorations, p.SettingsPayload{Environment: "home"}); err != nil {
			t.Fatal("strict completed enrollment publication could not refresh stores", err)
		}
		backend.mu.Lock()
		closed := backend.barrierClosedLocked()
		backend.mu.Unlock()
		if closed != sealed || backend.deps.prefs != prefs || backend.deps.restorations != restorations {
			t.Fatal("enrollment publication undid SCM seal or did not finish the ordinary transfer")
		}
	}
}
