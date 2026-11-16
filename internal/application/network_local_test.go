package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"netlaunch/internal/app"
	"netlaunch/internal/engine"
	"netlaunch/internal/policy"
	p "netlaunch/internal/serviceprotocol"
)

type macStopFixture struct {
	report   macRunReport
	request  func(context.Context) error
	wait     func(context.Context) error
	recover  func(context.Context) error
	company  func(context.Context, string, uint64, bool, bool) error
	personal func(context.Context, string, uint64, bool, bool) error
	auth     func(context.Context, string, string, uint64) error
}

func (f *macStopFixture) Matches(path string, file os.FileInfo) bool {
	return path == f.report.path && f.report.identity != nil && file != nil && os.SameFile(f.report.identity, file)
}
func (f *macStopFixture) Request(ctx context.Context) error              { return f.request(ctx) }
func (f *macStopFixture) WaitForStoppedReport(ctx context.Context) error { return f.wait(ctx) }
func (f *macStopFixture) RecoverVerified(ctx context.Context) error      { return f.recover(ctx) }
func (f *macStopFixture) Close() error                                   { return nil }
func (f *macStopFixture) SetMacCompany(ctx context.Context, id string, generation uint64, company, personal bool) error {
	return f.company(ctx, id, generation, company, personal)
}
func (f *macStopFixture) SetMacPersonal(ctx context.Context, id string, generation uint64, company, personal bool) error {
	return f.personal(ctx, id, generation, company, personal)
}
func (f *macStopFixture) AuthenticateMacCompany(ctx context.Context, profile, runtime string, generation uint64) error {
	return f.auth(ctx, profile, runtime, generation)
}

func makeMacReport(t *testing.T, phase string) macRunReport {
	t.Helper()
	dir := t.TempDir()
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	return macRunReport{path: dir, identity: info, present: true, reported: true, status: engine.Status{Phase: phase}}
}

func macBackendFixture(t *testing.T) (*Desktop, *atomic.Pointer[macRunReport]) {
	t.Helper()
	d := &Desktop{Profile: t.TempDir(), Runtime: t.TempDir()}
	ctx, cancel := context.WithCancel(t.Context())
	current := &atomic.Pointer[macRunReport]{}
	current.Store(&macRunReport{})
	d.localWorkspace = &localWorkspace{
		ctx: ctx, cancel: cancel, profile: d.ClientProfileID(),
		commands: app.DesktopCommands{Profile: d.Profile, Runtime: d.Runtime},
		records:  make(map[string]localWorkspaceRecord),
		network:  &macNetwork{revision: 15, inspect: func(string) macRunReport { return *current.Load() }},
	}
	t.Cleanup(d.CloseLocalWorkspace)
	return d, current
}

func macCall(t *testing.T, d *Desktop, method string, input any) (any, error) {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return d.ClientRequest(t.Context(), method, raw)
}

func macSnapshot(t *testing.T, d *Desktop) p.Snapshot {
	t.Helper()
	v, err := macCall(t, d, "service.snapshot", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	return v.(p.Snapshot)
}

func macMutation(s p.Snapshot, id string, kind p.Kind) p.Mutation {
	m := p.Mutation{RequestID: id, Kind: kind, ProfileID: s.ProfileID, RunRef: s.RunRef, ExpectedRevision: s.Revision}
	switch kind {
	case p.TakeoverStart:
		m.Start = &p.StartPayload{Mode: "validation", ValidationSeconds: 90, Channels: p.DesiredChannels{Company: true, Personal: true}}
	case p.AuthBegin:
		m.BeginAuth = &p.AuthBeginPayload{}
	case p.ChannelsSet:
		m.Channels = &p.DesiredChannels{Company: !s.Desired.Company, Personal: s.Desired.Personal}
	default:
		m.Stop = &p.StopPayload{}
	}
	return m
}

func TestMacCompanyControlUsesBoundGenerationAndAllowsPriorityStop(t *testing.T) {
	d, current := macBackendFixture(t)
	n := d.localWorkspace.network
	running := makeMacReport(t, "managed")
	intent := policy.DefaultIntent()
	running.status.DesiredChannels, running.status.AppliedChannels = &intent, &intent
	running.status.DarwinCompanyControl, running.status.TakeoverActive = true, true
	running.status.ChannelGeneration, running.status.AppliedGeneration = 9, 9
	current.Store(&running)
	started := make(chan struct{})
	stopped := running
	stopped.status.Phase, stopped.stop = "stopped", true
	var canceled, requested, authenticated atomic.Bool
	n.bind = func(ctx context.Context, profile string) (macRunStop, error) {
		if profile != d.Profile {
			return nil, errors.New("wrong profile")
		}
		return &macStopFixture{
			report: running,
			company: func(ctx context.Context, id string, generation uint64, company, personal bool) error {
				if id != "switch" || generation != 9 || company || !personal {
					return errors.New("native call was not Company-only and generation-bound")
				}
				close(started)
				<-ctx.Done()
				canceled.Store(true)
				return ctx.Err()
			},
			auth: func(_ context.Context, profile, runtime string, generation uint64) error {
				authenticated.Store(profile == d.Profile && runtime == d.Runtime && generation == 9)
				return nil
			},
			request: func(context.Context) error {
				requested.Store(true)
				current.Store(&stopped)
				return nil
			},
			wait: func(context.Context) error { return nil },
		}, nil
	}
	s := macSnapshot(t, d)
	if !s.MacCompanyControl || s.TakeoverState != "managed_reported" {
		t.Fatal(s)
	}
	auth := macMutation(s, "refresh", p.AuthBegin)
	if _, err := macCall(t, d, "service.submit", auth); err != nil {
		t.Fatal(err)
	}
	if op := macCompleted(t, d, "refresh"); op.Error != nil || !authenticated.Load() || op.Phase != "authenticated" {
		t.Fatal(op)
	}
	s = macSnapshot(t, d)
	wrong := macMutation(s, "both", p.ChannelsSet)
	wrong.Channels.Personal = false
	_, err := macCall(t, d, "service.submit", wrong)
	macErrorCode(t, err, "INVALID_PARAMS")
	change := macMutation(s, "switch", p.ChannelsSet)
	if _, err = macCall(t, d, "service.submit", change); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("native company operation not dispatched")
	}
	if pending := macSnapshot(t, d); pending.MacCompanyControl || pending.TakeoverState != "applying_company" {
		t.Fatal(pending)
	}
	// An already-rendered same-run STOP may race the native apply status.
	stop := macMutation(s, "stop-company", p.TakeoverStop)
	if _, err := macCall(t, d, "service.submit", stop); err != nil {
		t.Fatal(err)
	}
	if op := macCompleted(t, d, "stop-company"); op.Error != nil || !requested.Load() || !canceled.Load() {
		t.Fatal(op)
	}
	if op := macCompleted(t, d, "switch"); op.Error == nil || op.Error.Code != "MAC_OPERATION_INTERRUPTED" {
		t.Fatal(op)
	}
}

func TestMacPersonalControlRequiresNativeProofAndPreservesCompany(t *testing.T) {
	d, current := macBackendFixture(t)
	n := d.localWorkspace.network
	running := makeMacReport(t, "managed")
	start := policy.ChannelIntent{Company: true, Personal: true, Environment: "home"}
	running.status.DesiredChannels, running.status.AppliedChannels = &start, &start
	running.status.TakeoverActive = true
	running.status.ChannelGeneration, running.status.AppliedGeneration = 9, 9
	current.Store(&running)
	initial := macSnapshot(t, d)
	change := macMutation(initial, "no-candidates", p.ChannelsSet)
	change.Channels = &p.DesiredChannels{Company: true}
	_, err := macCall(t, d, "service.submit", change)
	macErrorCode(t, err, "MAC_PERSONAL_UNAVAILABLE")

	eligible := running
	eligible.status.DarwinPersonalControl = true
	current.Store(&eligible)
	s := macSnapshot(t, d)
	if !s.MacPersonalControl || s.MacCompanyControl || s.Revision == initial.Revision {
		t.Fatal("wrong per-channel control capability", s)
	}
	both := macMutation(s, "both", p.ChannelsSet)
	both.Channels.Personal = false
	_, err = macCall(t, d, "service.submit", both)
	macErrorCode(t, err, "INVALID_PARAMS")
	same := macMutation(s, "same", p.ChannelsSet)
	same.Channels.Company = true
	_, err = macCall(t, d, "service.submit", same)
	macErrorCode(t, err, "INVALID_PARAMS")
	_, err = macCall(t, d, "service.submit", map[string]any{
		"kind": p.ChannelsSet, "request_id": "implicit-personal-off", "profile_id": s.ProfileID,
		"run_ref": s.RunRef, "expected_revision": s.Revision, "channels": map[string]bool{"company": true},
	})
	macErrorCode(t, err, "INVALID_PARAMS")

	started, proof := make(chan struct{}), make(chan struct{})
	var stopped, canceled atomic.Bool
	n.bind = func(_ context.Context, profile string) (macRunStop, error) {
		if profile != d.Profile {
			return nil, errors.New("wrong profile")
		}
		return &macStopFixture{
			report: running,
			personal: func(ctx context.Context, id string, generation uint64, company, personal bool) error {
				switch id {
				case "personal-off":
					if generation != 9 || !company || personal {
						return errors.New("Personal OFF did not preserve Company and generation")
					}
					// User-readable status alone is not protected acknowledgement.
					off := eligible
					intent := start
					intent.Personal = false
					off.status.DesiredChannels, off.status.AppliedChannels = &intent, &intent
					off.status.ChannelGeneration, off.status.AppliedGeneration = 10, 10
					current.Store(&off)
					close(started)
					select {
					case <-proof:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				case "personal-on":
					if generation != 10 || !company || !personal {
						return errors.New("Personal ON did not preserve Company and generation")
					}
					<-ctx.Done()
					canceled.Store(true)
					return ctx.Err()
				}
				return errors.New("unexpected personal request")
			},
			request: func(context.Context) error { stopped.Store(true); return nil },
			wait:    func(context.Context) error { return nil },
		}, nil
	}
	off := macMutation(s, "personal-off", p.ChannelsSet)
	off.Channels = &p.DesiredChannels{Company: true}
	if _, err := macCall(t, d, "service.submit", off); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("no native Personal OFF request")
	}
	if pending := macSnapshot(t, d); pending.TakeoverState != "applying_personal" || pending.MacPersonalControl {
		t.Fatal(pending)
	}
	pending, err := macCall(t, d, "service.operation", map[string]string{"operation_id": "personal-off"})
	if err != nil || pending.(p.Operation).Completed {
		t.Fatal("saved status prematurely completed Personal", err)
	}
	close(proof)
	if op := macCompleted(t, d, "personal-off"); op.Error != nil || op.Phase != "personal_applied" {
		t.Fatal(op)
	}
	s = macSnapshot(t, d)
	on := macMutation(s, "personal-on", p.ChannelsSet)
	on.Channels = &p.DesiredChannels{Company: true, Personal: true}
	if _, err := macCall(t, d, "service.submit", on); err != nil {
		t.Fatal(err)
	}
	stop := macMutation(s, "stop-personal", p.TakeoverStop)
	if _, err := macCall(t, d, "service.submit", stop); err != nil {
		t.Fatal(err)
	}
	if op := macCompleted(t, d, "stop-personal"); op.Error != nil || !stopped.Load() || !canceled.Load() {
		t.Fatal(op)
	}
	if op := macCompleted(t, d, "personal-on"); op.Error == nil || op.Error.Code != "MAC_OPERATION_INTERRUPTED" {
		t.Fatal(op)
	}
}

func macCompleted(t *testing.T, d *Desktop, id string) p.Operation {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		v, err := macCall(t, d, "service.operation", map[string]string{"operation_id": id})
		if err != nil {
			t.Fatal(err)
		}
		if op := v.(p.Operation); op.Completed {
			return op
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("desktop operation did not complete")
	return p.Operation{}
}

func macErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	var safe *Error
	if !errors.As(err, &safe) || safe.Code != code {
		t.Fatalf("wanted %s, got %v", code, err)
	}
}

func TestMacNetworkUsesNativeLifecycleForBoundRun(t *testing.T) {
	d, current := macBackendFixture(t)
	n := d.localWorkspace.network
	started, release := make(chan struct{}), make(chan struct{})
	running := makeMacReport(t, "ready")
	n.start = func(ctx context.Context, profile, bundle string, duration time.Duration, intent policy.ChannelIntent) error {
		if profile != d.Profile || bundle != d.Runtime || duration != 90*time.Second || intent != policy.DefaultIntent() {
			return errors.New("start not scoped to desktop")
		}
		close(started)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			current.Store(&running)
			return nil
		}
	}

	idle := macSnapshot(t, d)
	if idle.RunRef != "" || idle.Restored || idle.LocalExitProof != nil || idle.ServiceState != "local" || idle.TakeoverState != "idle" {
		t.Fatal(idle)
	}
	stale := macMutation(idle, "wrong-revision", p.TakeoverStart)
	stale.ExpectedRevision++
	_, err := macCall(t, d, "service.submit", stale)
	macErrorCode(t, err, "REVISION_CONFLICT")
	start := macMutation(idle, "start", p.TakeoverStart)
	if _, err := macCall(t, d, "service.submit", start); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("start not dispatched")
	}
	if _, err := macCall(t, d, "service.submit", start); err != nil {
		t.Fatal("replay of the active request rejected", err)
	}
	requestConflict := start
	requestConflict.ExpectedRevision++
	_, err = macCall(t, d, "service.submit", requestConflict)
	macErrorCode(t, err, "REQUEST_CONFLICT")
	_, err = macCall(t, d, "workspace.submit", map[string]any{"profile_id": idle.ProfileID, "action": "sync", "request_id": "busy-sync"})
	macErrorCode(t, err, "PROFILE_BUSY")
	close(release)
	if op := macCompleted(t, d, "start"); op.Error != nil || op.Phase != "ready_reported" || op.Restored {
		t.Fatal(op)
	}

	stopped := running
	stopped.status.Phase, stopped.stop = "stopped", true
	var requested, recovered atomic.Bool
	n.bind = func(_ context.Context, profile string) (macRunStop, error) {
		if profile != d.Profile {
			return nil, errors.New("foreign profile")
		}
		return &macStopFixture{
			report: running,
			request: func(context.Context) error {
				requested.Store(true)
				current.Store(&stopped)
				return nil
			},
			wait:    func(context.Context) error { return nil },
			recover: func(context.Context) error { recovered.Store(true); return nil },
		}, nil
	}
	active := macSnapshot(t, d)
	if active.RunRef == "" || active.TakeoverState != "ready_reported" {
		t.Fatal(active)
	}
	if _, err := macCall(t, d, "service.submit", macMutation(active, "stop", p.TakeoverStop)); err != nil {
		t.Fatal(err)
	}
	if op := macCompleted(t, d, "stop"); op.Error != nil || op.Restored || op.Phase != "stopped_reported" || !requested.Load() || recovered.Load() {
		t.Fatal(op)
	}
	reported := macSnapshot(t, d)
	if reported.Restored || reported.RunRef != active.RunRef || reported.TakeoverState != "stopped_reported" {
		t.Fatal(reported)
	}
	if _, err := macCall(t, d, "service.submit", macMutation(reported, "verify", p.ExitRestore)); err != nil {
		t.Fatal(err)
	}
	if op := macCompleted(t, d, "verify"); op.Error != nil || !op.Restored || op.RunRef != reported.RunRef || !recovered.Load() {
		t.Fatal(op)
	}
	if snapshot := macSnapshot(t, d); !snapshot.Restored || snapshot.TakeoverState != "restored" || snapshot.LocalExitProof != nil {
		t.Fatal(snapshot)
	}
}

func TestMacNetworkDoesNotRetargetRestoreOrReuseItsProof(t *testing.T) {
	d, current := macBackendFixture(t)
	first, next := makeMacReport(t, "stopped"), makeMacReport(t, "stopped")
	current.Store(&first)
	initial := macSnapshot(t, d)
	n := d.localWorkspace.network
	n.bind = func(context.Context, string) (macRunStop, error) {
		return &macStopFixture{report: next}, nil
	}
	_, err := macCall(t, d, "service.submit", macMutation(initial, "mismatch", p.ExitRestore))
	macErrorCode(t, err, "RUN_UNCONFIRMED")

	ready, release := make(chan struct{}), make(chan struct{})
	n.bind = func(context.Context, string) (macRunStop, error) {
		return &macStopFixture{report: first, recover: func(ctx context.Context) error {
			close(ready)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
				return nil
			}
		}}, nil
	}
	if _, err := macCall(t, d, "service.submit", macMutation(initial, "restore-old", p.ExitRestore)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("explicit recovery not dispatched")
	}
	current.Store(&next)
	during := macSnapshot(t, d)
	if during.RunRef == initial.RunRef || during.Restored {
		t.Fatal(during)
	}
	close(release)
	if op := macCompleted(t, d, "restore-old"); !op.Restored || op.RunRef != initial.RunRef {
		t.Fatal(op)
	}
	if after := macSnapshot(t, d); after.RunRef != during.RunRef || after.Restored {
		t.Fatal(after)
	}
}

func TestMacNetworkCloseCancelsPendingStart(t *testing.T) {
	d, _ := macBackendFixture(t)
	started := make(chan struct{})
	d.localWorkspace.network.start = func(ctx context.Context, _, _ string, _ time.Duration, _ policy.ChannelIntent) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	idle := macSnapshot(t, d)
	if _, err := macCall(t, d, "service.submit", macMutation(idle, "start", p.TakeoverStart)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("start not dispatched")
	}
	d.CloseLocalWorkspace()
	if op := macCompleted(t, d, "start"); op.Error == nil || op.Error.Code != "MAC_OPERATION_INTERRUPTED" || op.Restored {
		t.Fatal(op)
	}
	if _, err := macCall(t, d, "service.submit", macMutation(idle, "late", p.TakeoverStart)); err == nil {
		t.Fatal("closing bridge accepted a new start")
	}
}

func TestMacNetworkStopsOnlyExplicitValidLifecycleRequests(t *testing.T) {
	d, current := macBackendFixture(t)
	run := makeMacReport(t, "stopped")
	current.Store(&run)
	report := macSnapshot(t, d)
	partial := macMutation(report, "partial", p.TakeoverStart)
	partial.Start.ValidationSeconds = 2701
	_, err := macCall(t, d, "service.submit", partial)
	macErrorCode(t, err, "INVALID_PARAMS")
	toggle := p.Mutation{RequestID: "toggle", ProfileID: report.ProfileID, RunRef: report.RunRef, ExpectedRevision: report.Revision, Kind: p.ChannelsSet, Channels: &p.DesiredChannels{}}
	_, err = macCall(t, d, "service.submit", toggle)
	macErrorCode(t, err, "MAC_COMPANY_UNAVAILABLE")
	current.Store(&macRunReport{})
	lost := macSnapshot(t, d)
	if lost.TakeoverState != "unconfirmed" || !lost.RecoveryRequired || lost.Restored {
		t.Fatal(lost)
	}
	_, err = macCall(t, d, "service.submit", macMutation(lost, "unsafe", p.TakeoverStart))
	macErrorCode(t, err, "RECOVERY_REQUIRED")
}

func TestMacSavedRunPresentsNoPrivateFileValues(t *testing.T) {
	d, current := macBackendFixture(t)
	running := makeMacReport(t, "ready")
	running.status.Error = filepath.Join(d.Profile, "private-file")
	running.status.Channels = map[string]engine.ChannelStatus{
		"personal": {State: "ready", Reason: running.status.Error},
	}
	current.Store(&running)
	got := macSnapshot(t, d)
	if got.Personal.Reason != "" || got.Personal.State != "ready_reported" || got.Personal.Route != "unknown" {
		t.Fatal(got)
	}
}

func TestMacStartupChannelsAndAuthenticationUseSeparateOperations(t *testing.T) {
	d, current := macBackendFixture(t)
	n := d.localWorkspace.network
	var authCalls atomic.Int32
	n.auth = func(_ context.Context, profile, bundle string) error {
		if profile != d.Profile || bundle != d.Runtime {
			return errors.New("authentication target escaped desktop scope")
		}
		authCalls.Add(1)
		return nil
	}
	n.start = func(_ context.Context, profile, bundle string, duration time.Duration, intent policy.ChannelIntent) error {
		if profile != d.Profile || bundle != d.Runtime || duration != 0 {
			return errors.New("start not scoped to desktop")
		}
		if intent.Company && authCalls.Load() == 0 {
			return errors.Join(app.ErrMacAuthenticationRequired, errors.New("private failure omitted"))
		}
		return nil
	}
	for _, desired := range []p.DesiredChannels{{}, {Personal: true}, {Company: true}, {Company: true, Personal: true}} {
		s := macSnapshot(t, d)
		id := fmt.Sprintf("start-%t-%t", desired.Company, desired.Personal)
		m := macMutation(s, id, p.TakeoverStart)
		m.Start = &p.StartPayload{Mode: "daily", Channels: desired}
		if _, err := macCall(t, d, "service.submit", m); err != nil {
			t.Fatal(err)
		}
		completed := macCompleted(t, d, id)
		if desired.Company {
			if completed.Error == nil || completed.Error.Code != "MAC_AUTH_REQUIRED" || !completed.Error.Retryable {
				t.Fatal(completed)
			}
		} else if completed.Error != nil {
			t.Fatal(completed)
		}
	}
	if authCalls.Load() != 0 {
		t.Fatal("starting unexpectedly initiated authentication")
	}
	partial := map[string]any{"request_id": "missing-channel", "profile_id": d.ClientProfileID(),
		"expected_revision": macSnapshot(t, d).Revision, "kind": p.TakeoverStart,
		"start": map[string]any{"mode": "daily", "channels": map[string]any{"company": false}}}
	_, err := macCall(t, d, "service.submit", partial)
	macErrorCode(t, err, "INVALID_PARAMS")
	s := macSnapshot(t, d)
	auth := macMutation(s, "auth", p.AuthBegin)
	_, err = macCall(t, d, "service.submit", map[string]any{
		"kind": p.AuthBegin, "request_id": "foreign", "profile_id": s.ProfileID, "expected_revision": s.Revision,
		"begin_auth": map[string]any{"profile": "/foreign"},
	})
	macErrorCode(t, err, "INVALID_PARAMS")
	if _, err := macCall(t, d, "service.submit", auth); err != nil {
		t.Fatal(err)
	}
	if completed := macCompleted(t, d, "auth"); completed.Error != nil || completed.Phase != "authenticated" || authCalls.Load() != 1 {
		t.Fatal(completed, authCalls.Load())
	}
	if _, err := macCall(t, d, "service.submit", auth); err != nil || authCalls.Load() != 1 {
		t.Fatal("idempotent auth re-opened the terminal", err, authCalls.Load())
	}
	s = macSnapshot(t, d)
	resume := macMutation(s, "start-authorized", p.TakeoverStart)
	resume.Start = &p.StartPayload{Mode: "daily", Channels: p.DesiredChannels{Company: true}}
	if _, err := macCall(t, d, "service.submit", resume); err != nil {
		t.Fatal(err)
	}
	if completed := macCompleted(t, d, "start-authorized"); completed.Error != nil || completed.Phase != "ready_reported" {
		t.Fatal(completed)
	}
	active := makeMacReport(t, "ready")
	current.Store(&active)
	byRun := macMutation(macSnapshot(t, d), "unresolved-auth", p.AuthBegin)
	_, err = macCall(t, d, "service.submit", byRun)
	macErrorCode(t, err, "MAC_COMPANY_UNAVAILABLE")
	byRun.RequestID, byRun.RunRef = "unresolved-idle-auth", ""
	_, err = macCall(t, d, "service.submit", byRun)
	macErrorCode(t, err, "RECOVERY_REQUIRED")
}

func TestMacSnapshotDistinguishesDesiredFromAppliedChannels(t *testing.T) {
	d, current := macBackendFixture(t)
	run := makeMacReport(t, "ready")
	run.status.DesiredChannels = &policy.ChannelIntent{}
	run.status.AppliedChannels = &policy.ChannelIntent{}
	run.status.TakeoverActive = true
	run.status.ChannelGeneration, run.status.AppliedGeneration = 2, 1
	run.status.Channels = map[string]engine.ChannelStatus{
		"company":  {State: "ready", Reason: "disabled_blocked", PathState: "blocked"},
		"personal": {State: "ready", Reason: "disabled_direct", PathState: "physical_direct"},
	}
	current.Store(&run)
	if s := macSnapshot(t, d); s.Desired.Company || s.Desired.Personal || s.Company.Route != "unknown" || s.Personal.Route != "unknown" {
		t.Fatal(s)
	}
	applied := run
	applied.status.AppliedGeneration = applied.status.ChannelGeneration
	current.Store(&applied)
	if s := macSnapshot(t, d); s.Company.Route != "blocked_reported" || s.Personal.Route != "direct_reported" {
		t.Fatal(s)
	}
	stopped := applied
	stopped.stop = true
	current.Store(&stopped)
	if s := macSnapshot(t, d); s.Company.Route != "unknown" || s.Personal.Route != "unknown" {
		t.Fatal(s)
	}
}
