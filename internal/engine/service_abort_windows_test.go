//go:build windows

package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/winservice"
)

func TestPreparationAbortPartitionsRestoredOldReleaseBeforeCurrentPin(t *testing.T) {
	oldImage := []byte("old independently protected helper fixture")
	sum := sha256.Sum256(oldImage)
	oldPin := hex.EncodeToString(sum[:])
	newPin := strings.Repeat("b", 64)
	current := ServicePreparationReference{"profile", "new-run-ref", "instance"}
	old := servicePreparationClaim{Version: 1, ServicePreparationReference: ServicePreparationReference{"profile", "old-run-ref", "instance"}, RunID: "netlaunch-" + strings.Repeat("a", 32), ExecutorSID: "S-1-5-18", LifecycleSHA256: oldPin}
	matching, err := partitionPreparationClaim(old, old.RunID, current, newPin)
	if err != nil || matching {
		t.Fatal("old release was compared to current helper pin", matching, err)
	}
	m := Manifest{Version: 1, OwnerSID: "S-1-5-18", Service: &ServiceRunBinding{ProfileID: old.ProfileID, RunRef: old.BindingRunRef, ServiceInstance: old.ServiceInstance, ExecutorSID: "S-1-5-18", LifecycleSHA256: oldPin}}
	raw, _ := json.Marshal(m)
	digest, err := historicalPreparationSourceDigest(old, raw, oldImage)
	if err != nil || digest != runSpecDigest(immutableRunSpec(m)) {
		t.Fatal("own protected source not preserved", digest, err)
	}
	// Model the independent strict receipt's Source.SpecDigest binding. Neither
	// the current image pin nor a bare unrelated claim authorizes this history.
	receiptDigest := runSpecDigest(immutableRunSpec(m))
	if digest != receiptDigest || old.LifecycleSHA256 == newPin {
		t.Fatal("fixture does not exercise a restored old release")
	}
	called := false
	if err := verifyHistoricalPreparationEvidence(old, raw, oldImage, func(ref ServicePreparationReference, runID, pin, spec string) (bool, error) {
		called = true
		return ref == old.ServicePreparationReference && runID == old.RunID && pin == oldPin && spec == receiptDigest, nil
	}); err != nil || !called {
		t.Fatal("old frozen bytes and independent receipt did not verify", err)
	}
	if err := verifyHistoricalPreparationEvidence(old, raw, oldImage, func(ServicePreparationReference, string, string, string) (bool, error) { return false, nil }); err == nil {
		t.Fatal("unrelated bare claim bypassed strict receipt")
	}
	if err := verifyHistoricalPreparationEvidence(old, raw, oldImage, nil); err == nil {
		t.Fatal("missing receipt verifier accepted")
	}
	currentClaim := old
	currentClaim.ServicePreparationReference = current
	currentClaim.RunID = "netlaunch-" + strings.Repeat("c", 32)
	currentClaim.LifecycleSHA256 = newPin
	matching, err = partitionPreparationClaim(currentClaim, currentClaim.RunID, current, newPin)
	if err != nil || !matching {
		t.Fatal("new abort could not match its own release", err)
	}
	p := preparationCensusProof([]servicePreparationEvidence{{RunID: old.RunID}, {RunID: currentClaim.RunID, MatchingClaim: true, AdminAbsent: true}}, nil)
	if !p.Clean || len(p.RetainedRunIDs) != 1 || p.RetainedRunIDs[0] != currentClaim.RunID {
		t.Fatal("verified old history blocked new abort", p)
	}
	if _, err := historicalPreparationSourceDigest(old, raw, []byte("changed helper")); err == nil {
		t.Fatal("changed historical helper accepted")
	}
	if _, err := historicalPreparationSourceDigest(old, raw, nil); err == nil {
		t.Fatal("manifest without frozen bytes accepted as completed old run")
	}
	old.LifecycleSHA256 = newPin
	if _, err := historicalPreparationSourceDigest(old, raw, oldImage); err == nil {
		t.Fatal("old source was blessed with current hash")
	}
}

func TestPreparationAbortInterruptedAtomicTempRemainsIncomplete(t *testing.T) {
	p := preparationCensusProof([]servicePreparationEvidence{{RunID: "partial", MatchingClaim: true, AdminAbsent: true, Problem: "unknown .write-fixture atomic material retained"}}, nil)
	if p.Clean || p.IdentityCensusComplete || len(p.Errors) == 0 {
		t.Fatal("forced interruption with unattributed temp became clean", p)
	}
}

func TestPreparationAbortSnapshotFailureHasNoRunButRetainsStopBarrier(t *testing.T) {
	p := preparationCensusProof(nil, nil)
	if !p.Clean || !p.NeverBound || !p.IdentityCensusComplete || !p.NeverServed || !p.PreparedOnly || len(p.RetainedRunIDs) != 0 {
		t.Fatal(p)
	}
	r := ServicePreparationReference{"profile", "run-ref", "instance"}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	name := preparationAbortName(r)
	if name != preparationAbortName(r) || strings.ContainsAny(name, `\/:`) {
		t.Fatal("unstable or path-bearing stop marker", name)
	}
	r.BindingRunRef = "other-run"
	if preparationAbortName(r) == name {
		t.Fatal("stop marker crossed a run binding")
	}
}

func TestPreparationNativeStartCannotBypassDurableBinder(t *testing.T) {
	m := Manifest{Version: 1, Service: &ServiceRunBinding{ProfileID: "profile", RunRef: "ref", ServiceInstance: "instance"}}
	run := "netlaunch-" + strings.Repeat("a", 32)
	b := winservice.Binding{ProfileID: "profile", RunRef: "ref", ServiceInstance: "instance", PreparedRunID: run, SpecDigest: runSpecDigest(immutableRunSpec(m)), ExecutorSID: "S-1-5-18"}
	if err := verifyServicePreparedStartBinding(m, run, b); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*winservice.Binding){
		func(v *winservice.Binding) { v.PreparedRunID = "" },
		func(v *winservice.Binding) { v.SpecDigest = "" },
		func(v *winservice.Binding) { v.RunRef = "other" },
		func(v *winservice.Binding) { v.ServiceInstance = "other" },
		func(v *winservice.Binding) { v.ExecutorSID = "S-1-5-21-1" },
	} {
		bad := b
		alter(&bad)
		if err := verifyServicePreparedStartBinding(m, run, bad); err == nil {
			t.Fatal("unprepared or changed service run reached native start")
		}
	}
}

func TestPreparationAbortKnownPartialBeforeServeIsRetained(t *testing.T) {
	p := preparationCensusProof([]servicePreparationEvidence{{RunID: "netlaunch-fixture", MatchingClaim: true, AdminAbsent: true}}, nil)
	if !p.Clean || len(p.RetainedRunIDs) != 1 || p.RetainedRunIDs[0] != "netlaunch-fixture" {
		t.Fatal(p)
	}
}

func TestPreparationAbortUnknownOrPrivateMaterialCannotClearBinding(t *testing.T) {
	for _, rows := range [][]servicePreparationEvidence{
		{{Problem: "empty unclaimed directory after mkdir failure"}},
		{{RunID: "partial", MatchingClaim: true, AdminAbsent: true, Problem: "malformed manifest"}},
		{{RunID: "partial", MatchingClaim: true, AdminAbsent: true, Problem: "unknown runtime file"}},
		{{RunID: "begun", MatchingClaim: true, AdminAbsent: false}},
	} {
		p := preparationCensusProof(rows, nil)
		if p.Clean || len(p.Errors) == 0 {
			t.Fatal("unknown or previously initialized material reported clean", p)
		}
	}
	if p := preparationCensusProof(nil, []string{"unreadable census"}); p.Clean || p.IdentityCensusComplete {
		t.Fatal(p)
	}
}

func TestPreparationReferenceRejectsPathsAndRequiresWholeBinding(t *testing.T) {
	for _, r := range []ServicePreparationReference{{}, {"../profile", "run-ref", "instance"}, {"profile", "", "instance"}, {"profile", "run-ref", ""}, {"profile", `C:\run`, "instance"}} {
		if r.Validate() == nil {
			t.Fatal("unsafe unprepared reference accepted", r)
		}
	}
}

func TestPreparationMaterialAllowlistUsesProtectedManifest(t *testing.T) {
	m := runtimebundle.Manifest{Version: 1, OS: "windows", Arch: "amd64"}
	for i := 0; i < 18; i++ {
		m.Files = append(m.Files, runtimebundle.File{Path: fmt.Sprintf("bin/component-%02d.dll", i), SHA256: strings.Repeat("a", 64)})
	}
	allowed, err := preparationAllowedPaths(m)
	if err != nil || !allowed["runtime/bin"] {
		t.Fatal(allowed, err)
	}
	for _, name := range []string{"runtime/bin/arbitrary.exe", "state.json", "run-spec.json", "powershell.exe"} {
		if _, present := allowed[name]; present {
			t.Fatal("unreviewed material allowed", name)
		}
	}
	for _, filename := range []string{"../other", `C:\arbitrary.exe`, "bin/../../other", m.Files[1].Path} {
		bad := m
		bad.Files = append([]runtimebundle.File(nil), m.Files...)
		bad.Files[0].Path = filename
		if _, err = preparationAllowedPaths(bad); err == nil {
			t.Fatal("unsafe runtime path accepted", filename)
		}
	}
}
