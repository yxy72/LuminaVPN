package winservice

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func retiredJournalFixture(t *testing.T) (*rotatingFiles, installJournal) {
	t.Helper()
	files, previous, captured := retiredInstallFixture(t)
	target, err := retiredEnrollmentTarget(previous, captured)
	if err != nil {
		t.Fatal(err)
	}
	j := installJournal{Version: 1, Action: "bootstrap", Phase: "prepared", ReleaseDigest: strings.Repeat("a", 64), Image: `C:\Program Files\LuminaVPN\lumina-service.exe`, Previous: &previous, Target: target}
	if err = beginInstallJournal(files, j); err != nil {
		t.Fatal(err)
	}
	j.Phase = "services_ready"
	if err = writeInstallJournal(files, j); err != nil {
		t.Fatal(err)
	}
	return files, j
}

func TestInstallJournalResumesExactRetiredRotationBeforeAndAfterBindingPublication(t *testing.T) {
	for _, window := range []string{"before_binding", "after_binding"} {
		t.Run(window, func(t *testing.T) {
			files, j := retiredJournalFixture(t)
			files.failBinding = window == "before_binding"
			first, firstErr := publishJournalEnrollment(files, j)
			if window == "before_binding" && firstErr == nil || window == "after_binding" && firstErr != nil {
				t.Fatal(first, firstErr)
			}
			// Simulate a new installer process that saw no provisioning checkpoint.
			files.failBinding = false
			if _, _, err := inspectJournalEnrollment(files, j); err != nil {
				t.Fatal("exact protected publication cannot be inspected after restart", err)
			}
			current, err := publishJournalEnrollment(files, j)
			if err != nil || !journalPublicationMatches(j, current) {
				t.Fatal("exact interrupted publication did not resume", current, err)
			}
			if window == "after_binding" && current != first {
				t.Fatal("retry extended revision or minted another receipt")
			}
			proofs := &RestorationStore{files: files, enrolled: current}
			if clean, err := proofs.Verify(current); err != nil || !clean {
				t.Fatal("resumed enrollment lost strict original proof", err)
			}
			j.Phase, j.Published = "provisioned", &current
			if err = writeInstallJournal(files, j); err != nil {
				t.Fatal(err)
			}
			if again, err := publishJournalEnrollment(files, j); err != nil || again != current {
				t.Fatal("provisioned retry changed the frozen publication", again, err)
			}
		})
	}
}

func TestInstallJournalRejectsDifferentRetiredTargetOrMissingRotationEvidence(t *testing.T) {
	for _, alter := range []string{"target", "old_receipt", "new_receipt", "retirement_marker", "binding", "intent"} {
		t.Run(alter, func(t *testing.T) {
			files, j := retiredJournalFixture(t)
			current, err := publishJournalEnrollment(files, j)
			if err != nil {
				t.Fatal(err)
			}
			switch alter {
			case "target":
				j.Target.AuthenticationID = "later-login"
			case "old_receipt":
				delete(files.files, "restoration-"+j.Previous.LastRestorationID+".json")
			case "new_receipt":
				delete(files.files, "restoration-"+current.LastRestorationID+".json")
			case "retirement_marker":
				delete(files.files, "installation-retired.json")
			case "binding":
				current.AuthenticationID = "foreign"
				files.files[filepath.Join("bindings", current.ProfileID+".json")], _ = json.Marshal(current)
			case "intent":
				delete(files.files, "retired-login-"+enrollmentKey(*j.Previous)+".json")
			}
			before, _ := json.Marshal(files.files)
			if _, err := publishJournalEnrollment(files, j); err == nil {
				t.Fatal("unknown evidence or a later login was adopted")
			}
			after, _ := json.Marshal(files.files)
			if string(before) != string(after) {
				t.Fatal("rejected publication changed protected files")
			}
		})
	}
}

func TestInstallJournalFreshBindingWriteCanResumeButCannotClearForeignOrActiveBinding(t *testing.T) {
	for _, alter := range []string{"none", "tuple", "active"} {
		t.Run(alter, func(t *testing.T) {
			files, j := journalFixture()
			j.Phase = "services_ready"
			if current, exists, err := inspectJournalEnrollment(files, j); err != nil || exists || current != (Binding{}) {
				t.Fatal(current, exists, err)
			}
			first, err := publishJournalEnrollment(files, j)
			if err != nil || first != j.Target {
				t.Fatal(first, err)
			}
			binding := first
			switch alter {
			case "tuple":
				binding.AuthenticationID = "other"
			case "active":
				binding.RunRef, binding.Mode = "run-owned", "daily"
			}
			files.files[filepath.Join("bindings", binding.ProfileID+".json")], _ = json.Marshal(binding)
			again, err := publishJournalEnrollment(files, j)
			if alter == "none" && (err != nil || again != first) || alter != "none" && err == nil {
				t.Fatal("retry accepted changed unacknowledged binding", again, err)
			}
		})
	}
}

func TestInstallJournalCompletionDoesNotOverwriteAlreadyAcknowledgedOwnedRun(t *testing.T) {
	files, j := journalFixture()
	j.Phase = "services_ready"
	published, err := publishJournalEnrollment(files, j)
	if err != nil {
		t.Fatal(err)
	}
	j.Published, j.Phase = &published, "provisioned"
	active := published
	active.Revision++
	active.RunRef, active.Mode = "run-owned", "daily"
	files.files[filepath.Join("bindings", active.ProfileID+".json")], _ = json.Marshal(active)
	before, _ := json.Marshal(files.files)
	if got, err := publishJournalEnrollment(files, j); err != nil || got != published {
		t.Fatal("completion did not retain the original installation publication", got, err)
	}
	after, _ := json.Marshal(files.files)
	if string(before) != string(after) {
		t.Fatal("installer retry overwrote a later owned run")
	}
}

func TestInstallJournalPublishedRetiredBindingCannotRegainOldOrMissingReceipt(t *testing.T) {
	for _, receipt := range []string{"old", "missing", "empty"} {
		t.Run(receipt, func(t *testing.T) {
			files, j := retiredJournalFixture(t)
			published, err := publishJournalEnrollment(files, j)
			if err != nil {
				t.Fatal(err)
			}
			j.Published, j.Phase = &published, "provisioned"
			current := published
			switch receipt {
			case "old":
				current.LastRestorationID = j.Previous.LastRestorationID
			case "missing":
				current.LastRestorationID = "restore-missing"
			case "empty":
				current.LastRestorationID = ""
			}
			files.files[filepath.Join("bindings", current.ProfileID+".json")], _ = json.Marshal(current)
			if _, err := publishJournalEnrollment(files, j); err == nil {
				t.Fatal("published new login accepted an old, missing or absent strict proof")
			}
		})
	}
}

func TestInstallJournalRetirementCannotResumeWithChangedBindingOrMissingStrictProof(t *testing.T) {
	for _, altered := range []string{"none", "receipt", "active", "revision", "tuple"} {
		t.Run(altered, func(t *testing.T) {
			files, previous, _ := retiredInstallFixture(t)
			j := installJournal{Version: 1, Action: "retire", Phase: "prepared", ReleaseDigest: strings.Repeat("a", 64), Image: `C:\Program Files\LuminaVPN\lumina-service.exe`, Target: previous}
			actual := previous
			switch altered {
			case "receipt":
				delete(files.files, "restoration-"+previous.LastRestorationID+".json")
			case "active":
				actual.RunRef, actual.Mode = "run-owned", "daily"
			case "revision":
				actual.Revision++
			case "tuple":
				actual.AuthenticationID = "different"
			}
			files.files[filepath.Join("bindings", actual.ProfileID+".json")], _ = json.Marshal(actual)
			err := verifyJournalRetirement(files, j)
			if altered == "none" && err != nil || altered != "none" && err == nil {
				t.Fatal("retirement accepted unknown ownership/proof", err)
			}
		})
	}
}

func TestInstallJournalFixedRecoveryRemainsReachableOnlyAfterProvisioning(t *testing.T) {
	files, j := journalFixture()
	if installerJournalRecoveryAllowed(j, CommandRecover) {
		t.Fatal("unprovisioned journal enabled recovery")
	}
	j.Phase = "services_ready"
	if installerJournalRecoveryAllowed(j, CommandRecover) {
		t.Fatal("SCM creation without provisioning enabled recovery")
	}
	published, err := publishJournalEnrollment(files, j)
	if err != nil {
		t.Fatal(err)
	}
	j.Published, j.Phase = &published, "provisioned"
	control := machineControl{Version: 1, AllowedOwnerSID: published.OwnerSID, AllowedLogonSID: published.LogonSID, AuthenticationID: published.AuthenticationID, SessionID: published.SessionID, ProfileID: published.ProfileID, ServiceInstance: published.ServiceInstance, ServiceSID: "S-1-5-80-1", RecoveryServiceSID: "S-1-5-80-2", LogonEpoch: published.LogonEpoch}
	files.files["machine-control.json"], _ = json.Marshal(control)
	active := published
	active.Revision++
	active.RunRef, active.Mode = "run-owned", "daily"
	files.files[filepath.Join("bindings", active.ProfileID+".json")], _ = json.Marshal(active)
	before, _ := json.Marshal(files.files)
	if !installerJournalRecoveryAllowed(j, CommandRecover) || installerJournalRecoveryAllowed(j, CommandBootstrap) || installerJournalRecoveryAllowed(j, CommandUninstall) {
		t.Fatal("provisioned emergency authority was broadened beyond the fixed recovery entry")
	}
	gotControl, gotBinding, err := provisionedInstallerRecovery(files, j)
	if err != nil || gotControl != control || gotBinding != active {
		t.Fatal("SCM failure recovery cannot reach the exact provisioned active binding", gotBinding, err)
	}
	after, _ := json.Marshal(files.files)
	if string(before) != string(after) {
		t.Fatal("recovery authority inspection changed the journal or enrollment")
	}
	control.AuthenticationID = "other-login"
	files.files["machine-control.json"], _ = json.Marshal(control)
	if _, _, err = provisionedInstallerRecovery(files, j); err == nil {
		t.Fatal("fixed recovery accepted another login's control")
	}
}
