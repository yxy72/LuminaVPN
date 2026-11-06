package winservice

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

type rotatingFiles struct {
	*memoryStateFiles
	failBinding bool
}

func (f *rotatingFiles) Write(path string, data []byte) error {
	if f.failBinding && path == filepath.Join("bindings", "profile.json") {
		return errors.New("simulated atomic publication failure")
	}
	return f.memoryStateFiles.Write(path, data)
}
func rotationFixture(t *testing.T) (*rotatingFiles, *FileOwnershipStore, Binding, Binding) {
	t.Helper()
	files, base := fixtureStateFiles(t)
	base.LogonEpoch = "old-epoch"
	data, _ := json.Marshal(base)
	files.files[filepath.Join("bindings", "profile.json")] = data
	protected := &rotatingFiles{memoryStateFiles: files}
	store, err := newFileOwnershipStore(protected, base)
	if err != nil {
		t.Fatal(err)
	}
	active := base
	active.RunRef = "run-old"
	active.Mode = "daily"
	active.PreparedRunID = "netlaunch-" + strings.Repeat("a", 32)
	active.SpecDigest = strings.Repeat("b", 64)
	if err = store.Save(active); err != nil {
		t.Fatal(err)
	}
	id := fixtureRunRestoration(t, files, active)
	old := active
	clearRunBinding(&old)
	old.LastRestorationID = id
	old.Revision++
	if err = store.Save(old); err != nil {
		t.Fatal(err)
	}
	target := old
	target.LogonSID = "S-1-5-5-2-2"
	target.AuthenticationID = "new-auth"
	target.SessionID = 2
	target.LogonEpoch = "new-epoch"
	target.Revision++
	return protected, store, old, target
}
func TestDurableRotationKeepsFullTupleMutationAuthorizationAndRetiresOldLogin(t *testing.T) {
	files, store, old, target := rotationFixture(t)
	if store.Save(target) == nil {
		t.Fatal("regular owner save rotated logon identity")
	}
	rotated, err := store.Rotate(old, target)
	if err != nil {
		t.Fatal(err)
	}
	current, err := store.Lookup("profile")
	if err != nil || !sameEnrollment(current, target) || current.LastRestorationID == old.LastRestorationID {
		t.Fatal("new login tuple/publication missing")
	}
	restarted, err := newFileOwnershipStore(files, old)
	if err != nil {
		t.Fatal("permanent enrollment did not survive process restart", err)
	}
	fresh, _ := restarted.Lookup("profile")
	proofs := &RestorationStore{files: files, enrolled: fresh}
	if clean, err := proofs.Verify(fresh); err != nil || !clean {
		t.Fatal("strict old-run restore proof did not rebind to new login")
	}
	back := old
	back.Revision = rotated.Revision + 1
	if _, err = store.Rotate(rotated, back); err == nil {
		t.Fatal("retired GUI reclaimed current login")
	}
}
func TestPartialRotationCanResumeExactProtectedTargetAfterRestart(t *testing.T) {
	files, store, old, target := rotationFixture(t)
	files.failBinding = true
	if _, err := store.Rotate(old, target); err == nil {
		t.Fatal("failed durable publication acknowledged")
	}
	pending, err := store.Lookup("profile")
	if err != nil || pending.PendingEnrollmentID == "" {
		t.Fatal("fully evidenced publication intent was not retained", err)
	}
	oldPeer := testPeer()
	oldPeer.logonEpoch = old.LogonEpoch
	if authorize(oldPeer, pending, old.ExecutorSID, old.ServiceInstance) == nil || store.Save(old) == nil {
		t.Fatal("partial rotation allowed the retired tuple or ordinary save")
	}
	restarted, err := newFileOwnershipStore(files, old)
	if err != nil {
		t.Fatal("transient publication failure permanently locked host", err)
	}
	planned, err := restarted.PendingTarget(pending)
	if err != nil || !sameEnrollment(planned, target) {
		t.Fatal("protected target lost", err)
	}
	wrong := planned
	wrong.AuthenticationID = "different-login"
	if _, err = restarted.Rotate(pending, wrong); err == nil {
		t.Fatal("later caller replaced accepted target")
	}
	files.failBinding = false
	current, err := restarted.Rotate(pending, planned)
	if err != nil || current.PendingEnrollmentID != "" || current != planned {
		t.Fatal("exact publication did not resume", err)
	}
	proofs := &RestorationStore{files: files, enrolled: current}
	if clean, err := proofs.Verify(current); err != nil || !clean {
		t.Fatal("resume lost original strict proof", err)
	}
	if _, err = restarted.Rotate(current, old); err == nil {
		t.Fatal("old tuple reclaimed after resumed publication")
	}
}

func TestPendingRotationRejectsMissingOrConflictingProof(t *testing.T) {
	for _, corrupt := range []string{"intent", "old_receipt", "new_receipt"} {
		t.Run(corrupt, func(t *testing.T) {
			files, store, old, target := rotationFixture(t)
			files.failBinding = true
			_, _ = store.Rotate(old, target)
			pending, err := store.Lookup("profile")
			if err != nil {
				t.Fatal(err)
			}
			planned, err := store.PendingTarget(pending)
			if err != nil {
				t.Fatal(err)
			}
			switch corrupt {
			case "intent":
				data, _ := json.Marshal(retiredEnrollmentRecord{Version: 1, Binding: old})
				files.files["retired-login-"+enrollmentKey(old)+".json"] = data
			case "old_receipt":
				delete(files.files, "restoration-"+old.LastRestorationID+".json")
			case "new_receipt":
				receipt, _ := readRestoration(files, planned.LastRestorationID)
				receipt.Source.SpecDigest = strings.Repeat("d", 64)
				data, _ := json.Marshal(receipt)
				files.files["restoration-"+planned.LastRestorationID+".json"] = data
			}
			files.failBinding = false
			if _, err := newFileOwnershipStore(files, old); err == nil {
				t.Fatal("unknown rotation evidence accepted")
			}
		})
	}
}

func TestShutdownCanFinishPreviouslyRestoredPendingPublication(t *testing.T) {
	files, store, old, target := rotationFixture(t)
	files.failBinding = true
	_, _ = store.Rotate(old, target)
	files.failBinding = false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b, err := NewBroker(ctx, &fakeBackend{stop: func(context.Context, AuthorizedOperation, func(Progress)) (Completion, error) {
		t.Fatal("already strict-restored transfer started new recovery")
		return Completion{}, nil
	}}, store, &MemoryLedger{}, old.ExecutorSID, old.ServiceInstance)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	current, err := store.Lookup("profile")
	if err != nil || current.PendingEnrollmentID != "" || !sameEnrollment(current, target) {
		t.Fatal("SYSTEM shutdown did not finish protected same-target publication", err)
	}
}

func TestPendingAttachmentOnlyAcceptedForOriginalVerifiedTarget(t *testing.T) {
	files, store, old, target := rotationFixture(t)
	files.failBinding = true
	_, _ = store.Rotate(old, target)
	files.failBinding = false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b, err := NewBroker(ctx, &fakeBackend{stop: func(context.Context, AuthorizedOperation, func(Progress)) (Completion, error) {
		t.Fatal("publication-only repair repeated recovery")
		return Completion{}, nil
	}}, store, &MemoryLedger{}, old.ExecutorSID, old.ServiceInstance)
	if err != nil {
		t.Fatal(err)
	}
	actor := VerifiedPrincipal{sid: target.OwnerSID, logonSID: target.LogonSID, authenticationID: target.AuthenticationID, sessionID: target.SessionID, logonEpoch: target.LogonEpoch, profileID: target.ProfileID, desktopEligible: true, verified: true}
	wrong := actor
	wrong.authenticationID = "other"
	if _, err = b.Submit(ctx, wrong, attachmentMutation("wrong")); err == nil {
		t.Fatal("different target replaced pending intent")
	}
	op, err := b.Submit(ctx, actor, attachmentMutation("resume"))
	if err != nil {
		t.Fatal(err)
	}
	if result := waitAttachment(t, b, actor, op.ID); !result.Restored || result.Error != nil {
		t.Fatalf("resume failed: %#v", result)
	}
	current, _ := store.Lookup("profile")
	if !sameEnrollment(current, target) || current.PendingEnrollmentID != "" {
		t.Fatal("wrong resumed identity")
	}
}
