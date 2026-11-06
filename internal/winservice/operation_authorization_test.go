package winservice

import (
	"context"
	"testing"

	p "netlaunch/internal/serviceprotocol"
)

func loginHistoryFixture(t *testing.T) (*Broker, VerifiedPrincipal, VerifiedPrincipal, p.Operation) {
	t.Helper()
	old, current := ordinaryAttachPeer("1", 1), ordinaryAttachPeer("2", 2)
	b, _, _ := newTestBroker(t, &fakeBackend{stop: func(context.Context, AuthorizedOperation, func(Progress)) (Completion, error) {
		return Completion{Restored: true, RestorationID: "restore-mock"}, nil
	}}, attachBinding(old))
	prior, err := b.Submit(context.Background(), old, p.Mutation{RequestID: "prior", ProfileID: "profile", ExpectedRevision: 1, Kind: p.NodeSelect, Selection: &p.SelectionPayload{NodeID: "auto"}})
	if err != nil {
		t.Fatal(err)
	}
	waitAttachment(t, b, old, prior.ID)
	attachment, err := b.Submit(context.Background(), current, attachmentMutation("new-login"))
	if err != nil {
		t.Fatal(err)
	}
	if result := waitAttachment(t, b, current, attachment.ID); result.Error != nil || !result.Completed {
		t.Fatal("new login did not attach", result.Error)
	}
	return b, old, current, prior
}

func TestOperationHistoryUsesCurrentEnrollmentForCachedAndPersistedRecords(t *testing.T) {
	for _, cached := range []bool{true, false} {
		name := map[bool]string{true: "cached", false: "persisted"}[cached]
		t.Run(name, func(t *testing.T) {
			b, old, current, prior := loginHistoryFixture(t)
			if !cached {
				b.mu.Lock()
				delete(b.operations, prior.ID)
				b.mu.Unlock()
			}
			if _, err := b.Operation(context.Background(), old, prior.ID); err == nil {
				t.Fatal("retired login retained operation read authority")
			}
			result, err := b.Operation(context.Background(), current, prior.ID)
			if err != nil || result.ID != prior.ID || result.RequestID != prior.RequestID || !result.Completed {
				t.Fatal("current login could not inspect its own account/profile history", err)
			}
			for _, actor := range []VerifiedPrincipal{
				func() VerifiedPrincipal { v := current; v.sid = "S-1-5-21-2"; return v }(),
				func() VerifiedPrincipal { v := current; v.profileID = "other-profile"; return v }(),
			} {
				if _, err := b.Operation(context.Background(), actor, prior.ID); err == nil {
					t.Fatal("foreign owner/profile read operation history")
				}
			}
		})
	}
}

func TestAttachmentTargetMayReadOnlyItsOwnAcceptedOperationBeforeRotation(t *testing.T) {
	old, target := ordinaryAttachPeer("1", 1), ordinaryAttachPeer("2", 2)
	entered, release := make(chan struct{}), make(chan struct{})
	b, _, _ := newTestBroker(t, &fakeBackend{stop: func(context.Context, AuthorizedOperation, func(Progress)) (Completion, error) {
		close(entered)
		<-release
		return Completion{Restored: true, RestorationID: "restore-mock"}, nil
	}}, attachBinding(old))
	prior, err := b.Submit(context.Background(), old, p.Mutation{RequestID: "prior", ProfileID: "profile", ExpectedRevision: 1, Kind: p.NodeSelect, Selection: &p.SelectionPayload{NodeID: "auto"}})
	if err != nil {
		t.Fatal(err)
	}
	waitAttachment(t, b, old, prior.ID)
	attachment, err := b.Submit(context.Background(), target, attachmentMutation("new-login"))
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	for _, actor := range []VerifiedPrincipal{old, target} {
		if _, err := b.Operation(context.Background(), actor, prior.ID); err == nil {
			close(release)
			t.Fatal("enrollment barrier exposed another operation")
		}
	}
	result, err := b.Operation(context.Background(), target, attachment.ID)
	if err != nil || result.ID != attachment.ID || result.Completed {
		close(release)
		t.Fatal("verified attachment target could not follow its own accepted operation", err)
	}
	foreign := target
	foreign.profileID = "other-profile"
	if _, err = b.Operation(context.Background(), foreign, attachment.ID); err == nil {
		close(release)
		t.Fatal("attachment exception crossed profile identity")
	}
	close(release)
	if final := waitAttachment(t, b, target, attachment.ID); final.Error != nil || !final.Completed {
		t.Fatal("attachment did not finish", final.Error)
	}
}
