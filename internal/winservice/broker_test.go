package winservice

import (
	"context"
	"encoding/json"
	"errors"
	p "netlaunch/internal/serviceprotocol"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeBackend struct {
	snapshot  func(context.Context, Binding) (p.Snapshot, error)
	execute   func(context.Context, AuthorizedOperation, func(Progress)) (Completion, error)
	stop      func(context.Context, AuthorizedOperation, func(Progress)) (Completion, error)
	workspace func(context.Context) (Completion, error)
}

func (f *fakeBackend) Snapshot(ctx context.Context, b Binding) (p.Snapshot, error) {
	if f.snapshot != nil {
		return f.snapshot(ctx, b)
	}
	return p.Snapshot{ProfileID: b.ProfileID, Revision: b.Revision, RunRef: b.RunRef}, nil
}
func (f *fakeBackend) Execute(c context.Context, a AuthorizedOperation, pf func(Progress)) (Completion, error) {
	if f.execute != nil {
		return f.execute(c, a, pf)
	}
	return Completion{}, nil
}
func (f *fakeBackend) StopAndRestore(c context.Context, a AuthorizedOperation, pf func(Progress)) (Completion, error) {
	if f.stop != nil {
		return f.stop(c, a, pf)
	}
	return Completion{Restored: true}, nil
}
func (f *fakeBackend) Auth(context.Context, AuthorizedOperation, func(Progress)) (Completion, error) {
	return Completion{}, nil
}
func (f *fakeBackend) Workspace(c context.Context, _ VerifiedPrincipal, _ Binding, _ p.WorkspacePayload, _ func(Progress)) (Completion, error) {
	if f.workspace != nil {
		return f.workspace(c)
	}
	return Completion{}, nil
}
func testPeer() VerifiedPrincipal {
	return VerifiedPrincipal{sid: "S-1-5-21-1", logonSID: "S-1-5-5-1-1", authenticationID: "auth-1", sessionID: 1, verified: true, desktopEligible: true, profileID: "profile"}
}
func testPeerForProfile(profile string) VerifiedPrincipal {
	v := testPeer()
	v.profileID = profile
	return v
}
func testBinding(id string) Binding {
	v := testPeer()
	return Binding{ProfileID: id, OwnerSID: v.sid, LogonSID: v.logonSID, AuthenticationID: v.authenticationID, SessionID: v.sessionID, ExecutorSID: "S-1-5-18", ServiceInstance: "service-1", Revision: 1}
}
func newTestBroker(t *testing.T, f *fakeBackend, bindings ...Binding) (*Broker, *MemoryStore, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	store := &MemoryStore{Bindings: map[string]Binding{}}
	for _, b := range bindings {
		store.Bindings[b.ProfileID] = b
	}
	b, err := NewBroker(ctx, f, store, &MemoryLedger{}, "S-1-5-18", "service-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cancel)
	return b, store, cancel
}
func waitOperation(t *testing.T, b *Broker, id string) p.Operation {
	t.Helper()
	return waitOperationAs(t, b, id, testPeer())
}
func waitOperationAs(t *testing.T, b *Broker, id string, peer VerifiedPrincipal) p.Operation {
	t.Helper()
	until := time.Now().Add(2 * time.Second)
	for {
		op, err := b.Operation(context.Background(), peer, id)
		if err != nil {
			t.Fatal(err)
		}
		if op.Completed || op.Phase == "failed" {
			return op
		}
		if time.Now().After(until) {
			t.Fatal("operation did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}
func startMutation(id, profile string) p.Mutation {
	return p.Mutation{RequestID: id, ProfileID: profile, ExpectedRevision: 1, Kind: p.TakeoverStart, Start: &p.StartPayload{Mode: "daily"}}
}
func stopMutation(id, profile, run string) p.Mutation {
	return p.Mutation{RequestID: id, ProfileID: profile, RunRef: run, ExpectedRevision: 1, Kind: p.ExitRestore, Stop: &p.StopPayload{}}
}

func TestAcceptedOperationOutlivesCallerReadAndDetach(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	b, _, _ := newTestBroker(t, &fakeBackend{execute: func(ctx context.Context, _ AuthorizedOperation, _ func(Progress)) (Completion, error) {
		close(entered)
		select {
		case <-finish:
			return Completion{}, nil
		case <-ctx.Done():
			return Completion{}, ctx.Err()
		}
	}}, testBinding("profile"))
	ctx, cancel := context.WithCancel(context.Background())
	op, err := b.Submit(ctx, testPeer(), startMutation("request", "profile"))
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	cancel()
	close(finish)
	done := waitOperation(t, b, op.ID)
	if done.Error != nil || !done.Completed {
		t.Fatalf("GUI cancellation owned service work: %#v", done)
	}
}

func TestStopWaitsForStartupAndInvalidatesQueuedChannelWork(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	var calls, stops atomic.Int32
	b, _, _ := newTestBroker(t, &fakeBackend{execute: func(ctx context.Context, _ AuthorizedOperation, _ func(Progress)) (Completion, error) {
		calls.Add(1)
		close(entered)
		<-ctx.Done()
		<-finish
		return Completion{}, nil
	}, stop: func(context.Context, AuthorizedOperation, func(Progress)) (Completion, error) {
		stops.Add(1)
		return Completion{Restored: true}, nil
	}}, testBinding("profile"))
	start, err := b.Submit(context.Background(), testPeer(), startMutation("start", "profile"))
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	queued, err := b.Submit(context.Background(), testPeer(), p.Mutation{RequestID: "channels", ProfileID: "profile", ExpectedRevision: 1, RunRef: start.RunRef, Kind: p.ChannelsSet, Channels: &p.DesiredChannels{Personal: true}})
	if err != nil {
		t.Fatal(err)
	}
	stop, err := b.Submit(context.Background(), testPeer(), stopMutation("exit", "profile", start.RunRef))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if stops.Load() != 0 {
		t.Fatal("restored ACK raced ahead of still-running startup")
	}
	close(finish)
	done := waitOperation(t, b, stop.ID)
	if !done.Restored || done.Error != nil {
		t.Fatalf("stop failed: %#v", done)
	}
	old := waitOperation(t, b, queued.ID)
	if old.Error == nil || calls.Load() != 1 || stops.Load() != 1 {
		t.Fatalf("old work executed after stop: %#v calls=%d stops=%d", old, calls.Load(), stops.Load())
	}
	duplicate, err := b.Submit(context.Background(), testPeer(), stopMutation("exit", "profile", start.RunRef))
	if err != nil || duplicate.ID != stop.ID {
		t.Fatal("same request did not retain original restore acknowledgement")
	}
}

func TestQueuedStartCannotBeginAfterExitRestored(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	var starts atomic.Int32
	b, _, _ := newTestBroker(t, &fakeBackend{workspace: func(context.Context) (Completion, error) { close(entered); <-finish; return Completion{}, nil }, execute: func(context.Context, AuthorizedOperation, func(Progress)) (Completion, error) {
		starts.Add(1)
		return Completion{}, nil
	}}, testBinding("profile"))
	_, err := b.Submit(context.Background(), testPeer(), p.Mutation{RequestID: "workspace", ProfileID: "profile", ExpectedRevision: 1, Kind: p.Workspace, Workspace: &p.WorkspacePayload{Action: "sync"}})
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	start, err := b.Submit(context.Background(), testPeer(), startMutation("start", "profile"))
	if err != nil {
		t.Fatal(err)
	}
	stop, err := b.Submit(context.Background(), testPeer(), stopMutation("exit", "profile", start.RunRef))
	if err != nil {
		t.Fatal(err)
	}
	if op := waitOperation(t, b, stop.ID); !op.Restored {
		t.Fatal("stop did not restore")
	}
	close(finish)
	if op := waitOperation(t, b, start.ID); op.Error == nil || starts.Load() != 0 {
		t.Fatalf("late queued startup survived barrier: %#v", op)
	}
}

func TestStopForOtherProfileDoesNotCancelActiveRun(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	var cancelled atomic.Bool
	a := testBinding("profileA")
	a.RunRef = "run-A"
	b, _, _ := newTestBroker(t, &fakeBackend{execute: func(ctx context.Context, _ AuthorizedOperation, _ func(Progress)) (Completion, error) {
		close(entered)
		select {
		case <-ctx.Done():
			cancelled.Store(true)
			return Completion{}, ctx.Err()
		case <-finish:
			return Completion{}, nil
		}
	}}, a, testBinding("profileB"))
	op, err := b.Submit(context.Background(), testPeerForProfile("profileA"), p.Mutation{RequestID: "channels", ProfileID: "profileA", ExpectedRevision: 1, RunRef: "run-A", Kind: p.ChannelsSet, Channels: &p.DesiredChannels{Personal: true}})
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	stop, err := b.Submit(context.Background(), testPeerForProfile("profileB"), stopMutation("stopB", "profileB", ""))
	if err != nil {
		t.Fatal(err)
	}
	waitOperationAs(t, b, stop.ID, testPeerForProfile("profileB"))
	if cancelled.Load() {
		t.Fatal("B stop cancelled A")
	}
	close(finish)
	if value := waitOperationAs(t, b, op.ID, testPeerForProfile("profileA")); value.Error != nil {
		t.Fatalf("A stopped by foreign profile: %#v", value)
	}
}

func TestCallerAndExecutorIdentityAreNotRPCClaims(t *testing.T) {
	b, _, _ := newTestBroker(t, &fakeBackend{}, testBinding("profile"))
	for _, alter := range []func(*VerifiedPrincipal){func(v *VerifiedPrincipal) { v.sid = "foreign" }, func(v *VerifiedPrincipal) { v.sessionID = 2 }, func(v *VerifiedPrincipal) { v.authenticationID = "other-logon" }, func(v *VerifiedPrincipal) { v.verified = false }, func(v *VerifiedPrincipal) { v.desktopEligible = false }, func(v *VerifiedPrincipal) { v.profileID = "foreign" }} {
		peer := testPeer()
		alter(&peer)
		if _, err := b.Submit(context.Background(), peer, startMutation("request", "profile")); err == nil {
			t.Fatal("foreign caller authorized")
		}
	}
}

func TestQueuedOldRevisionFailsBeforeBackendExecution(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	var executed atomic.Int32
	binding := testBinding("profile")
	binding.RunRef = "run-A"
	b, store, _ := newTestBroker(t, &fakeBackend{workspace: func(context.Context) (Completion, error) { close(entered); <-finish; return Completion{}, nil }, execute: func(context.Context, AuthorizedOperation, func(Progress)) (Completion, error) {
		executed.Add(1)
		return Completion{}, nil
	}}, binding)
	_, err := b.Submit(context.Background(), testPeer(), p.Mutation{RequestID: "sync", ProfileID: "profile", ExpectedRevision: 1, Kind: p.Workspace, Workspace: &p.WorkspacePayload{Action: "sync"}})
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	queued, err := b.Submit(context.Background(), testPeer(), p.Mutation{RequestID: "channels", ProfileID: "profile", ExpectedRevision: 1, RunRef: "run-A", Kind: p.ChannelsSet, Channels: &p.DesiredChannels{}})
	if err != nil {
		t.Fatal(err)
	}
	binding.Revision = 2
	store.Save(binding)
	close(finish)
	op := waitOperation(t, b, queued.ID)
	if op.Error == nil || executed.Load() != 0 {
		t.Fatalf("stale queued config applied: %#v", op)
	}
}

func TestLedgerContainsNoCredentialsAndFirstFailureIsSticky(t *testing.T) {
	op := p.Operation{ID: "operation", Phase: "accepted"}
	setFailure(&op, "FIRST")
	setFailure(&op, "SECOND")
	if op.Error.Code != "FIRST" || op.FirstFailure.Code != "FIRST" {
		t.Fatal("first failure overwritten")
	}
	raw, _ := json.Marshal(op)
	if strings.Contains(string(raw), "password") || strings.Contains(string(raw), "otp") {
		t.Fatal("operation retained auth input")
	}
}
func TestPipeAclUsesExactDataRightsAndFixedFlags(t *testing.T) {
	sddl, err := PipeSDDL("S-1-5-80-1-2-3", "S-1-5-5-1-1")
	if err != nil || !strings.Contains(sddl, "0x00100083") || strings.Contains(sddl, "GW") || PipeClientRights != 0x00100083 || PipeClientRights&4 != 0 || PipeFirstInstance != 0x80000 || PipeRejectRemote != 8 {
		t.Fatal("unsafe pipe access or flags")
	}
	if _, err := PipeSDDL("bad;GA", "S-1-5-5-1-1"); err == nil {
		t.Fatal("SDDL injection accepted")
	}
}

var _ = errors.New

func TestInstalledValidationPolicyCannotBeOverriddenByDailyRPC(t *testing.T) {
	b, _, _ := newTestBroker(t, &fakeBackend{}, testBinding("profile"))
	b.validationOnly = true
	if _, err := b.Submit(context.Background(), testPeer(), startMutation("daily", "profile")); err == nil {
		t.Fatal("validation-only host accepted daily RPC")
	}
	mutation := startMutation("validation", "profile")
	mutation.Start.Mode = "validation"
	mutation.Start.ValidationSeconds = 120
	accepted, err := b.Submit(context.Background(), testPeer(), mutation)
	if err != nil {
		t.Fatal(err)
	}
	if final := waitOperation(t, b, accepted.ID); final.Error != nil {
		t.Fatal(final.Error)
	}
}
