package winservice

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	p "netlaunch/internal/serviceprotocol"
)

func ordinaryAttachPeer(epoch string, session uint32) VerifiedPrincipal {
	v := testPeer()
	v.desktopEligible = true
	v.profileID = "profile"
	v.logonEpoch = epoch
	v.sessionID = session
	v.authenticationID = "auth-" + epoch
	v.logonSID = "S-1-5-5-1-" + epoch
	return v
}
func attachBinding(v VerifiedPrincipal) Binding {
	b := testBinding("profile")
	b.OwnerSID = v.sid
	b.LogonSID = v.logonSID
	b.AuthenticationID = v.authenticationID
	b.SessionID = v.sessionID
	b.LogonEpoch = v.logonEpoch
	return b
}
func attachmentMutation(request string) p.Mutation {
	return p.Mutation{RequestID: request, ProfileID: "profile", Kind: p.AttachEnrollment, Attach: &p.AttachPayload{}}
}
func waitAttachment(t *testing.T, b *Broker, v VerifiedPrincipal, id string) p.Operation {
	t.Helper()
	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		operation, err := b.Operation(context.Background(), v, id)
		if err != nil {
			t.Fatal(err)
		}
		if operation.Completed || operation.Error != nil {
			return operation
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("attachment did not complete")
	return p.Operation{}
}

func TestNewLoginAttachmentOutlivesRPCAndRestoresBeforeRotating(t *testing.T) {
	oldPeer, newPeer := ordinaryAttachPeer("1", 1), ordinaryAttachPeer("2", 2)
	binding := attachBinding(oldPeer)
	binding.RunRef = "run-old"
	entered, finish := make(chan struct{}), make(chan struct{})
	var stops atomic.Int32
	b, store, _ := newTestBroker(t, &fakeBackend{stop: func(_ context.Context, a AuthorizedOperation, _ func(Progress)) (Completion, error) {
		if !a.ServiceStop() || a.Binding().AuthenticationID != oldPeer.authenticationID {
			t.Error("attachment did not restore the old service-owned binding")
		}
		stops.Add(1)
		close(entered)
		<-finish
		return Completion{Restored: true, RestorationID: "restore-mock"}, nil
	}}, binding)
	ctx, cancel := context.WithCancel(context.Background())
	op, err := b.Submit(ctx, newPeer, attachmentMutation("attach1"))
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	<-entered
	if view, err := b.Snapshot(context.Background(), oldPeer, "profile"); err != nil || view.ServiceState != "attaching" || view.TakeoverState == "ready" {
		t.Fatal("old snapshot remained ready during transfer")
	}
	if _, err = b.Submit(context.Background(), oldPeer, p.Mutation{RequestID: "late", ProfileID: "profile", ExpectedRevision: 1, RunRef: binding.RunRef, Kind: p.NodeSelect, Selection: &p.SelectionPayload{NodeID: "auto"}}); err == nil {
		t.Fatal("old mutation crossed transfer barrier")
	}
	duplicate, err := b.Submit(context.Background(), newPeer, attachmentMutation("proxy-restarted"))
	if err != nil || duplicate.ID != op.ID {
		t.Fatal("proxy restart created a second cleanup job")
	}
	current, _ := store.Lookup("profile")
	if current.AuthenticationID != oldPeer.authenticationID {
		t.Fatal("tuple rotated before strict restore")
	}
	close(finish)
	final := waitAttachment(t, b, newPeer, op.ID)
	if final.Error != nil || !final.Restored || !final.Completed || stops.Load() != 1 {
		t.Fatalf("attachment failed: %#v", final)
	}
	current, _ = store.Lookup("profile")
	if current.AuthenticationID != newPeer.authenticationID || current.LogonEpoch != newPeer.logonEpoch || current.RunRef != "" {
		t.Fatal("new kernel identity was not durably attached")
	}
	if _, err = b.Submit(context.Background(), oldPeer, attachmentMutation("old-gui-poll")); err == nil {
		t.Fatal("retired GUI reclaimed the new login")
	}
}
func TestAttachmentRejectsIneligibleForeignProfileAndUnknownEpoch(t *testing.T) {
	old := ordinaryAttachPeer("1", 1)
	b, _, _ := newTestBroker(t, &fakeBackend{}, attachBinding(old))
	for _, change := range []func(*VerifiedPrincipal){func(v *VerifiedPrincipal) { v.desktopEligible = false }, func(v *VerifiedPrincipal) { v.sid = "S-1-5-21-2" }, func(v *VerifiedPrincipal) { v.profileID = "foreign" }, func(v *VerifiedPrincipal) { v.logonEpoch = "" }} {
		actor := ordinaryAttachPeer("2", 2)
		change(&actor)
		if _, err := b.Submit(context.Background(), actor, attachmentMutation("request")); err == nil {
			t.Fatal("unverified/ineligible/foreign attachment accepted")
		}
	}
}

func TestUnfilteredAdministratorAttachmentPreservesLoginRotationBoundary(t *testing.T) {
	old := ordinaryAttachPeer("1", 1)
	facts := testUnfilteredAdminFacts()
	facts.AuthenticationID, facts.LogonSID, facts.LogonEpoch, facts.SessionID = "auth-2", "S-1-5-5-1-2", "2", 2
	facts.TokenType, facts.ImpersonationLevel = 2, 2
	current, err := verifiedDesktopPrincipal(facts)
	if err != nil {
		t.Fatal(err)
	}
	binding := attachBinding(old)
	binding.RunRef = "run-old"
	var restores atomic.Int32
	b, store, _ := newTestBroker(t, &fakeBackend{stop: func(_ context.Context, a AuthorizedOperation, _ func(Progress)) (Completion, error) {
		if a.Binding().AuthenticationID != old.authenticationID {
			t.Error("restoration changed the old login")
		}
		restores.Add(1)
		return Completion{Restored: true, RestorationID: "restore-mock"}, nil
	}}, binding)
	op, err := b.Submit(context.Background(), current, attachmentMutation("unfiltered-attach"))
	if err != nil {
		t.Fatal(err)
	}
	final := waitAttachment(t, b, current, op.ID)
	if final.Error != nil || !final.Completed || !final.Restored || restores.Load() != 1 {
		t.Fatal("unfiltered login did not restore and attach", final)
	}
	latest, _ := store.Lookup("profile")
	if latest.AuthenticationID != facts.AuthenticationID || latest.LogonEpoch != facts.LogonEpoch || latest.OwnerSID != binding.OwnerSID || latest.ProfileID != binding.ProfileID {
		t.Fatal("rotation changed permanent ownership or lost current login")
	}
	if _, err := b.Submit(context.Background(), old, attachmentMutation("retired-unfiltered")); err == nil {
		t.Fatal("retired login reclaimed current enrollment")
	}
}
func TestFailedRestoreNeverRotatesEnrollment(t *testing.T) {
	old, newer := ordinaryAttachPeer("1", 1), ordinaryAttachPeer("2", 2)
	binding := attachBinding(old)
	binding.RunRef = "run-old"
	b, store, _ := newTestBroker(t, &fakeBackend{stop: func(context.Context, AuthorizedOperation, func(Progress)) (Completion, error) {
		return Completion{}, errors.New("readback unknown")
	}}, binding)
	op, err := b.Submit(context.Background(), newer, attachmentMutation("request"))
	if err != nil {
		t.Fatal(err)
	}
	if final := waitAttachment(t, b, newer, op.ID); final.Error == nil || final.Restored {
		t.Fatal("unknown recovery transferred ownership")
	}
	current, _ := store.Lookup("profile")
	if !sameEnrollment(current, binding) || current.RunRef != binding.RunRef {
		t.Fatal("failed restore changed durable owner")
	}
}
func TestSnapshotStartedBeforeAttachmentCannotPublishLateOldReady(t *testing.T) {
	old, newer := ordinaryAttachPeer("1", 1), ordinaryAttachPeer("2", 2)
	binding := attachBinding(old)
	binding.RunRef = "run-old"
	reading, releaseRead, stopping, releaseStop := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	b, _, _ := newTestBroker(t, &fakeBackend{snapshot: func(context.Context, Binding) (p.Snapshot, error) {
		close(reading)
		<-releaseRead
		return p.Snapshot{ServiceState: "available", TakeoverState: "ready"}, nil
	}, stop: func(context.Context, AuthorizedOperation, func(Progress)) (Completion, error) {
		close(stopping)
		<-releaseStop
		return Completion{Restored: true, RestorationID: "restore-mock"}, nil
	}}, binding)
	view := make(chan p.Snapshot, 1)
	go func() { snapshot, _ := b.Snapshot(context.Background(), old, "profile"); view <- snapshot }()
	<-reading
	op, err := b.Submit(context.Background(), newer, attachmentMutation("attach"))
	if err != nil {
		t.Fatal(err)
	}
	<-stopping
	close(releaseRead)
	if snapshot := <-view; snapshot.ServiceState != "attaching" || snapshot.TakeoverState == "ready" {
		t.Fatal("in-flight old read crossed enrollment barrier")
	}
	close(releaseStop)
	if done := waitAttachment(t, b, newer, op.ID); done.Error != nil {
		t.Fatal(done.Error)
	}
}
