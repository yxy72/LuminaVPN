//go:build windows && windows_client_predecessor_repair

package winservice

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func unpreparedPredecessorFixture(now time.Time) (Binding, PredecessorRepairExpectation) {
	source := testBinding("profile")
	source.RunRef = "run-accepted"
	source.Mode = "validation"
	source.Deadline = now.Add(-time.Minute)
	source.ServiceHostPID = 471
	source.ServiceHostBirth = "known-filetime"
	source.ServiceHostSHA256 = strings.Repeat("a", 64)
	source.LifecycleSHA256 = strings.Repeat("b", 64)
	expected := PredecessorRepairExpectation{
		ReleaseID: predecessorRepairReleaseID, ServiceSHA256: source.ServiceHostSHA256, LifecycleSHA256: source.LifecycleSHA256,
		OwnerSID: source.OwnerSID, ProfileID: source.ProfileID, ServiceInstance: source.ServiceInstance, RunRef: source.RunRef,
	}
	return source, expected
}

func TestRepairRequiresExpiredExactUnpreparedPredecessor(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	source, expected := unpreparedPredecessorFixture(now)
	if err := validateUnpreparedPredecessor(source, expected, now); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Binding)
	}{
		{"another run", func(b *Binding) { b.RunRef = "run-another" }},
		{"another owner", func(b *Binding) { b.OwnerSID = "S-1-5-21-99" }},
		{"unexpired", func(b *Binding) { b.Deadline = now }},
		{"prepared", func(b *Binding) { b.PreparedRunID = "netlaunch-" + strings.Repeat("b", 32) }},
		{"partial prepared pin", func(b *Binding) { b.SpecDigest = strings.Repeat("c", 64) }},
		{"unknown host", func(b *Binding) { b.ServiceHostBirth = "" }},
		{"foreign lifecycle", func(b *Binding) { b.LifecycleSHA256 = strings.Repeat("c", 64) }},
		{"pending enrolment", func(b *Binding) { b.PendingEnrollmentID = "rotation" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := source
			tc.mutate(&bad)
			if err := validateUnpreparedPredecessor(bad, expected, now); err == nil {
				t.Fatal("ineligible predecessor binding accepted")
			}
		})
	}
}

func TestRepairPublishesStrictReceiptBeforeClearingOnlyTheOldRun(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	source, _ := unpreparedPredecessorFixture(now)
	files := &memoryStateFiles{files: map[string][]byte{}}
	input, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := files.Write(filepath.Join("bindings", source.ProfileID+".json"), input); err != nil {
		t.Fatal(err)
	}
	owners, err := newFileOwnershipStore(files, source)
	if err != nil {
		t.Fatal(err)
	}
	proof := restorationFlags{
		Clean: true, NeverBound: true, NeverServed: true, PreparedOnly: true, IdentityCensusComplete: true,
		Started: now, Finished: now.Add(time.Second),
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishUnpreparedPredecessor(files, owners, source, raw, now.Add(time.Second), now.Add(2*time.Second)); err == nil {
		t.Fatal("predating preparation-abort proof accepted")
	}
	if got, err := owners.Lookup(source.ProfileID); err != nil || !samePredecessorBinding(got, source) {
		t.Fatal("unverified evidence changed owned state", err)
	}
	if err := publishUnpreparedPredecessor(files, owners, source, raw, now, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := owners.Lookup(source.ProfileID)
	if err != nil || got.RunRef != "" || !sameEnrollment(got, source) || got.Revision != source.Revision {
		t.Fatal("repair did not preserve the enrolled binding", err)
	}
	receipt, err := readRestoration(files, got.LastRestorationID)
	if err != nil || receipt.Scope != "unprepared" || !samePredecessorBinding(receipt.Source, source) {
		t.Fatal("strict receipt does not bind the old run", err)
	}
	if _, exists := files.files["recovery-ack.json"]; exists {
		t.Fatal("repair must leave nonce acknowledgement to the old recovery service")
	}
}
