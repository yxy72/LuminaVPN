package winservice

import (
	"encoding/json"
	"errors"
	"path/filepath"
)

func journalPublicationMatches(j installJournal, binding Binding) bool {
	if !validInstallJournalBinding(binding) || !sameEnrollment(binding, j.Target) {
		return false
	}
	if j.Previous != nil && !sameEnrollment(*j.Previous, j.Target) {
		if binding.LastRestorationID == "" || binding.LastRestorationID == j.Previous.LastRestorationID {
			return false
		}
	}
	copy := binding
	copy.LastRestorationID = j.Target.LastRestorationID
	return copy == j.Target
}

// inspectJournalEnrollment is read-only. It accepts only the frozen old binding,
// the exact pending target already protected by Rotate, or that target's exact
// completed publication. A later login cannot replace an interrupted target.
func inspectJournalEnrollment(files protectedStateFiles, j installJournal) (Binding, bool, error) {
	if err := validateInstallJournal(j); err != nil || j.Action != "bootstrap" {
		return Binding{}, false, errors.New("bootstrap journal required")
	}
	if j.Previous != nil {
		if err := verifyRetiredInstallation(files, *j.Previous); err != nil {
			return Binding{}, false, err
		}
	}
	_, err := files.Read(filepath.Join("bindings", j.Target.ProfileID+".json"))
	if errors.Is(err, errProtectedStateMissing) && j.Previous == nil && j.Published == nil {
		return Binding{}, false, nil
	}
	if err != nil {
		return Binding{}, false, err
	}
	owners, err := newFileOwnershipStore(files, j.Target)
	if err != nil {
		return Binding{}, false, err
	}
	current, err := owners.Lookup(j.Target.ProfileID)
	if err != nil {
		return Binding{}, false, err
	}
	if j.Published != nil {
		// The acknowledged service may already own a later run. Resuming only
		// installation completion must not clear it or reuse its old clean proof.
		if !sameEnrollment(current, *j.Published) || current.PendingEnrollmentID != "" || current.Revision < j.Published.Revision {
			return Binding{}, false, errors.New("published installer enrollment changed")
		}
		if current.RunRef == "" && (current.LastRestorationID != "" || j.Previous != nil) {
			proofs := &RestorationStore{files: files, enrolled: current}
			if clean, err := proofs.Verify(current); err != nil || !clean {
				return Binding{}, false, errors.New("published installer restoration evidence changed")
			}
		}
		return current, true, nil
	}
	if j.Previous == nil {
		if current != j.Target {
			return Binding{}, false, errors.New("fresh installer binding changed")
		}
		return current, true, nil
	}
	if current == *j.Previous {
		return current, true, nil
	}
	if current.PendingEnrollmentID != "" {
		planned, err := owners.PendingTarget(current)
		if err != nil || !journalPublicationMatches(j, planned) {
			return Binding{}, false, errors.New("pending installer enrollment target changed")
		}
		return current, true, nil
	}
	if !journalPublicationMatches(j, current) {
		return Binding{}, false, errors.New("retired installer binding changed")
	}
	if !sameEnrollment(*j.Previous, j.Target) {
		// All services are stopped and the installer lock is held. This helper
		// only reads the same intent/receipt chain used by PendingTarget; it
		// handles a crash after Rotate's binding write but before our checkpoint.
		planned, err := owners.pendingTarget(*j.Previous)
		if err != nil || planned != current {
			return Binding{}, false, errors.New("rotated installer publication has no exact intent")
		}
	}
	return current, true, nil
}

func publishJournalEnrollment(files protectedStateFiles, j installJournal) (Binding, error) {
	if j.Phase != "services_ready" && j.Phase != "provisioned" {
		return Binding{}, errors.New("services must be verified before enrollment publication")
	}
	current, exists, err := inspectJournalEnrollment(files, j)
	if err != nil {
		return Binding{}, err
	}
	if j.Published != nil {
		return *j.Published, nil
	}
	if j.Previous == nil {
		if !exists {
			data, err := json.Marshal(j.Target)
			if err != nil {
				return Binding{}, err
			}
			if err = files.Write(filepath.Join("bindings", j.Target.ProfileID+".json"), data); err != nil {
				return Binding{}, err
			}
		}
		return j.Target, nil
	}
	owners, err := newFileOwnershipStore(files, *j.Previous)
	if err != nil {
		return Binding{}, err
	}
	if current.PendingEnrollmentID != "" {
		planned, err := owners.PendingTarget(current)
		if err != nil {
			return Binding{}, err
		}
		return owners.Rotate(current, planned)
	}
	if current == *j.Previous {
		return provisionRetiredEnrollment(files, current, j.Target)
	}
	return current, nil
}

func verifyJournalRetirement(files protectedStateFiles, j installJournal) error {
	if validateInstallJournal(j) != nil || j.Action != "retire" {
		return errors.New("strict retirement journal required")
	}
	owners, err := newFileOwnershipStore(files, j.Target)
	if err != nil {
		return err
	}
	current, err := owners.Lookup(j.Target.ProfileID)
	if err != nil || current != j.Target {
		return errors.New("retirement ownership changed")
	}
	proofs := &RestorationStore{files: files, enrolled: j.Target}
	clean, err := proofs.Verify(current)
	if err != nil || !clean {
		return errors.New("retirement has no exact strict restoration publication")
	}
	return nil
}

func installerJournalRecoveryAllowed(j installJournal, command Command) bool {
	return command == CommandRecover && validateInstallJournal(j) == nil && j.Action == "bootstrap" && j.Phase == "provisioned" && j.Published != nil
}

// A crash after starting the provisioned service must not disable its fixed
// SYSTEM recovery entry. This is read-only authority for StopMain/RecoverExact,
// not permission to resume installation or choose another enrollment.
func provisionedInstallerRecovery(files protectedStateFiles, j installJournal) (machineControl, Binding, error) {
	if !installerJournalRecoveryAllowed(j, CommandRecover) {
		return machineControl{}, Binding{}, errors.New("installer has no provisioned recovery entry")
	}
	current, exists, err := inspectJournalEnrollment(files, j)
	if err != nil || !exists {
		return machineControl{}, Binding{}, errors.New("provisioned recovery enrollment unavailable")
	}
	data, err := files.Read("machine-control.json")
	if err != nil {
		return machineControl{}, Binding{}, err
	}
	var control machineControl
	if decodeState(data, &control) != nil || !sidText.MatchString(control.RecoveryServiceSID) {
		return machineControl{}, Binding{}, errors.New("provisioned recovery control unavailable")
	}
	bound, err := control.binding()
	if err != nil || !sameEnrollment(bound, *j.Published) {
		return machineControl{}, Binding{}, errors.New("provisioned recovery control changed enrollment")
	}
	return control, current, nil
}
