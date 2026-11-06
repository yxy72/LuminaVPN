package winservice

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func retiredInstallFixture(t *testing.T) (*rotatingFiles, Binding, Binding) {
	t.Helper()
	files, _, previous, target := rotationFixture(t)
	data, err := json.Marshal(retiredInstallation{Version: 1, ProfileID: previous.ProfileID, RestorationID: previous.LastRestorationID, ServiceInstance: previous.ServiceInstance})
	if err != nil {
		t.Fatal(err)
	}
	files.files["installation-retired.json"] = data
	captured := Binding{ProfileID: target.ProfileID, OwnerSID: target.OwnerSID, LogonSID: target.LogonSID, AuthenticationID: target.AuthenticationID, SessionID: target.SessionID, ExecutorSID: target.ExecutorSID, LogonEpoch: target.LogonEpoch, Revision: 1}
	return files, previous, captured
}

func TestRetiredReinstallPublishesNewLoginReceiptWithoutReusingOldTuple(t *testing.T) {
	files, previous, captured := retiredInstallFixture(t)
	current, err := provisionRetiredEnrollment(files, previous, captured)
	if err != nil {
		t.Fatal(err)
	}
	if !samePermanentEnrollment(current, previous) || !sameEnrollmentIdentity(current, captured) || current.Revision != previous.Revision+1 || current.LastRestorationID == previous.LastRestorationID {
		t.Fatal("reinstall lost ownership or retained the old login receipt", current)
	}
	var stored Binding
	if decodeState(files.files[filepath.Join("bindings", current.ProfileID+".json")], &stored) != nil || stored != current {
		t.Fatal("rotated binding was not durably published")
	}
	proofs := &RestorationStore{files: files, enrolled: current}
	if clean, err := proofs.Verify(current); err != nil || !clean {
		t.Fatal("new login did not retain strict original restoration evidence", err)
	}
	prior, err := readRestoration(files, previous.LastRestorationID)
	if err != nil || !sameEnrollment(prior.Enrollment, previous) {
		t.Fatal("old receipt was overwritten", err)
	}
	stale := current
	stale.LastRestorationID = previous.LastRestorationID
	if clean, err := proofs.Verify(stale); err == nil || clean {
		t.Fatal("old login receipt accepted for the new login")
	}
	store, err := newFileOwnershipStore(files, current)
	if err != nil {
		t.Fatal(err)
	}
	if retired, err := store.Retired(previous); err != nil || !retired {
		t.Fatal("old login was not durably retired", err)
	}
}

func TestRetiredSameLoginRetainsMatchingReceiptAndPermanentOwnership(t *testing.T) {
	files, previous, _ := retiredInstallFixture(t)
	captured := previous
	captured.ServiceInstance, captured.LastRestorationID = "", ""
	current, err := provisionRetiredEnrollment(files, previous, captured)
	if err != nil || !sameEnrollment(current, previous) || current.LastRestorationID != previous.LastRestorationID || current.Revision != previous.Revision+1 {
		t.Fatal("same-login reinstall changed its valid restoration identity", current, err)
	}
}

func TestRetiredReinstallRejectsForeignOrUnprovedEnrollmentWithoutWrites(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*rotatingFiles, *Binding, *Binding)
	}{
		{"owner", func(_ *rotatingFiles, _ *Binding, b *Binding) { b.OwnerSID = "S-1-5-21-99" }},
		{"profile", func(_ *rotatingFiles, _ *Binding, b *Binding) { b.ProfileID = "other" }},
		{"executor", func(_ *rotatingFiles, _ *Binding, b *Binding) { b.ExecutorSID = "S-1-5-19" }},
		{"session", func(_ *rotatingFiles, _ *Binding, b *Binding) { b.SessionID = 0 }},
		{"epoch", func(_ *rotatingFiles, _ *Binding, b *Binding) { b.LogonEpoch = "" }},
		{"logon", func(_ *rotatingFiles, _ *Binding, b *Binding) { b.LogonSID = "invalid" }},
		{"auth", func(_ *rotatingFiles, _ *Binding, b *Binding) { b.AuthenticationID = "" }},
		{"active", func(_ *rotatingFiles, b *Binding, _ *Binding) { b.RunRef = "still-active" }},
		{"revision_overflow", func(_ *rotatingFiles, b *Binding, _ *Binding) { b.Revision = ^uint64(0) }},
		{"missing_retirement", func(f *rotatingFiles, _ *Binding, _ *Binding) { delete(f.files, "installation-retired.json") }},
		{"missing_receipt", func(f *rotatingFiles, b *Binding, _ *Binding) {
			delete(f.files, "restoration-"+b.LastRestorationID+".json")
		}},
		{"invalid_proof", func(f *rotatingFiles, b *Binding, _ *Binding) {
			r, _ := readRestoration(f, b.LastRestorationID)
			r.Proof = json.RawMessage(`{"clean":false}`)
			f.files["restoration-"+b.LastRestorationID+".json"], _ = json.Marshal(r)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			files, previous, captured := retiredInstallFixture(t)
			test.mutate(files, &previous, &captured)
			before, _ := json.Marshal(files.files)
			if _, err := provisionRetiredEnrollment(files, previous, captured); err == nil {
				t.Fatal("unknown or foreign retired state was replaced")
			}
			after, _ := json.Marshal(files.files)
			if string(before) != string(after) {
				t.Fatal("rejected retirement changed protected state")
			}
		})
	}
}

func TestRetiredReinstallPublicationFailureRetainsProtectedRotationIntent(t *testing.T) {
	files, previous, captured := retiredInstallFixture(t)
	files.failBinding = true
	if _, err := provisionRetiredEnrollment(files, previous, captured); err == nil {
		t.Fatal("failed binding publication was acknowledged")
	}
	store, err := newFileOwnershipStore(files, previous)
	if err != nil {
		t.Fatal("rotation lost its exact recoverable publication intent", err)
	}
	pending, err := store.Lookup(previous.ProfileID)
	if err != nil || pending.PendingEnrollmentID == "" {
		t.Fatal("failed rotation silently retained an ordinary old binding", err)
	}
	planned, err := store.PendingTarget(pending)
	if err != nil || !sameEnrollmentIdentity(planned, captured) || planned.LastRestorationID == previous.LastRestorationID {
		t.Fatal("new login proof/target lost on publication failure", err)
	}
}
