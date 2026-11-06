package winservice

import (
	"encoding/json"
	"errors"
	"strings"

	p "netlaunch/internal/serviceprotocol"
)

const installJournalPath = "installer-journal.json"

// installJournal freezes one installer plan. Protected files provide atomic
// publication; this record does not replace OS observation or restoration proof.
type installJournal struct {
	Version       int      `json:"version"`
	Action        string   `json:"action"`
	Phase         string   `json:"phase"`
	ReleaseDigest string   `json:"release_digest"`
	Image         string   `json:"image"`
	Previous      *Binding `json:"previous,omitempty"`
	Target        Binding  `json:"target"`
	Published     *Binding `json:"published,omitempty"`
}

func installJournalPhase(action, phase string) (int, bool) {
	var phases []string
	switch action {
	case "bootstrap":
		phases = []string{"prepared", "services_ready", "provisioned", "complete"}
	case "retire":
		phases = []string{"prepared", "main_deleted", "recovery_deleted", "complete"}
	default:
		return 0, false
	}
	for index, value := range phases {
		if value == phase {
			return index, true
		}
	}
	return 0, false
}

func validInstallJournalBinding(binding Binding) bool {
	return ValidProfileID(binding.ProfileID) && sidText.MatchString(binding.OwnerSID) && binding.OwnerSID != "S-1-5-18" && sidText.MatchString(binding.LogonSID) && binding.ExecutorSID == "S-1-5-18" && p.ValidID(binding.ServiceInstance) && validOwnedBinding(binding, binding) && binding.RunRef == "" && binding.PendingEnrollmentID == ""
}

func validateInstallJournal(j installJournal) error {
	phase, known := installJournalPhase(j.Action, j.Phase)
	if j.Version != 1 || !known || !digestText.MatchString(j.ReleaseDigest) || j.Image == "" || strings.ContainsRune(j.Image, '\x00') || !validInstallJournalBinding(j.Target) {
		return errors.New("invalid installer journal plan")
	}
	if j.Action == "retire" {
		if j.Previous != nil || j.Published != nil || j.Target.LastRestorationID == "" {
			return errors.New("invalid retirement journal identity")
		}
		return nil
	}
	if j.Target.LogonEpoch == "" {
		return errors.New("bootstrap journal requires captured login epoch")
	}
	if j.Previous == nil {
		if j.Target.Revision != 1 || j.Target.LastRestorationID != "" {
			return errors.New("fresh installer journal must have initial revision and no receipt")
		}
	} else {
		previous := *j.Previous
		if !validInstallJournalBinding(previous) || previous.LastRestorationID == "" || !samePermanentEnrollment(previous, j.Target) || previous.Revision == ^uint64(0) || j.Target.Revision != previous.Revision+1 || j.Target.LastRestorationID != previous.LastRestorationID {
			return errors.New("invalid retired installer journal target")
		}
	}
	if phase < 2 {
		if j.Published != nil {
			return errors.New("installer journal published before provisioning")
		}
		return nil
	}
	if j.Published == nil || !validInstallJournalBinding(*j.Published) || !sameEnrollment(*j.Published, j.Target) || j.Published.Revision != j.Target.Revision {
		return errors.New("installer journal has no matching provisioning publication")
	}
	if j.Previous == nil && *j.Published != j.Target {
		return errors.New("fresh provisioning publication changed its frozen binding")
	}
	if j.Previous != nil {
		if !sameEnrollment(*j.Previous, j.Target) {
			if j.Published.LastRestorationID == "" || j.Published.LastRestorationID == j.Previous.LastRestorationID {
				return errors.New("new login requires a new restoration publication")
			}
		} else if j.Published.LastRestorationID != j.Previous.LastRestorationID {
			return errors.New("same login changed its restoration publication")
		}
	}
	return nil
}

// readInstallJournal reports absence only for the protected-store missing
// sentinel. Unknown or unreadable state must never become a fresh installation.
func readInstallJournal(files protectedStateFiles) (installJournal, bool, error) {
	if files == nil {
		return installJournal{}, true, errors.New("installer journal files unavailable")
	}
	data, err := files.Read(installJournalPath)
	if errors.Is(err, errProtectedStateMissing) {
		return installJournal{}, false, nil
	}
	if err != nil {
		return installJournal{}, true, err
	}
	var j installJournal
	if err = decodeState(data, &j); err != nil {
		return installJournal{}, true, err
	}
	if err = validateInstallJournal(j); err != nil {
		return installJournal{}, true, err
	}
	return j, true, nil
}

func sameInstallJournalPlan(a, b installJournal) bool {
	if a.Version != b.Version || a.Action != b.Action || a.ReleaseDigest != b.ReleaseDigest || a.Image != b.Image || a.Target != b.Target || (a.Previous == nil) != (b.Previous == nil) {
		return false
	}
	return a.Previous == nil || *a.Previous == *b.Previous
}

// beginInstallJournal starts only a new prepared cycle. The caller must hold
// the process-wide installer lock and independently prove the required SCM
// absence/strict retirement or exact restoration before beginning this plan.
// Completed history is replaced atomically, never deleted to manufacture absence.
func beginInstallJournal(files protectedStateFiles, j installJournal) error {
	if err := validateInstallJournal(j); err != nil {
		return err
	}
	if j.Phase != "prepared" || j.Published != nil {
		return errors.New("installer cycle must begin prepared")
	}
	previous, exists, err := readInstallJournal(files)
	if err != nil {
		return err
	}
	if exists && previous.Phase != "complete" {
		return errors.New("pending installer cycle cannot be replaced")
	}
	return publishInstallJournal(files, j)
}

// writeInstallJournal advances one frozen plan under the caller's installer
// lock. It cannot begin a different cycle or change an existing publication.
func writeInstallJournal(files protectedStateFiles, j installJournal) error {
	if err := validateInstallJournal(j); err != nil {
		return err
	}
	previous, exists, err := readInstallJournal(files)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("installer journal must begin before phase publication")
	}
	oldPhase, _ := installJournalPhase(previous.Action, previous.Phase)
	newPhase, _ := installJournalPhase(j.Action, j.Phase)
	if !sameInstallJournalPlan(previous, j) || newPhase < oldPhase {
		return errors.New("installer journal plan changed or phase regressed")
	}
	if previous.Published != nil && (j.Published == nil || *previous.Published != *j.Published) {
		return errors.New("installer provisioning publication changed")
	}
	return publishInstallJournal(files, j)
}

func publishInstallJournal(files protectedStateFiles, j installJournal) error {
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return files.Write(installJournalPath, data)
}

func journalCallerMatches(j installJournal, captured Binding) bool {
	return j.Action == "bootstrap" && validateInstallJournal(j) == nil && sameEnrollmentIdentity(j.Target, captured)
}

// installJournalServices accepts only the two fixed service names below. The
// Windows implementation must reject foreign configurations and unknown state;
// Remove may delete only this plan's stopped service and must confirm absence.
type installJournalServices interface {
	Ensure(name string, allowPartial bool) error
	Verify(name string) error
	Remove(name string) error
	Absent(name string) error
}

func requireInstallJournal(files protectedStateFiles, j installJournal) error {
	if err := validateInstallJournal(j); err != nil {
		return err
	}
	current, exists, err := readInstallJournal(files)
	if err != nil {
		return err
	}
	if !exists || !sameInstallJournalPlan(current, j) || current.Phase != j.Phase || (current.Published == nil) != (j.Published == nil) || (current.Published != nil && *current.Published != *j.Published) {
		return errors.New("exact durable installer phase required before SCM operation")
	}
	return nil
}

// resumeBootstrapServices requires the caller's process-wide installer lock.
// Only the durable prepared phase permits completing partial SCM creation.
func resumeBootstrapServices(files protectedStateFiles, j installJournal, services installJournalServices) (installJournal, error) {
	if j.Action != "bootstrap" || services == nil {
		return j, errors.New("bootstrap journal and fixed services required")
	}
	if err := requireInstallJournal(files, j); err != nil {
		return j, err
	}
	if j.Phase == "prepared" {
		if err := services.Ensure(ServiceName, true); err != nil {
			return j, err
		}
		if err := services.Ensure(RecoveryServiceName, true); err != nil {
			return j, err
		}
	}
	for _, name := range []string{ServiceName, RecoveryServiceName} {
		if err := services.Verify(name); err != nil {
			return j, err
		}
	}
	if j.Phase == "prepared" {
		next := j
		next.Phase = "services_ready"
		if err := writeInstallJournal(files, next); err != nil {
			return j, err
		}
		j = next
	}
	return j, nil
}

// resumeRetirementServices resumes only the frozen deletion plan. Every delete
// is followed by durable progress before the next delete; after both phases,
// absence checks cannot delete a service that has subsequently reappeared.
func resumeRetirementServices(files protectedStateFiles, j installJournal, services installJournalServices) (installJournal, error) {
	if j.Action != "retire" || services == nil {
		return j, errors.New("retirement journal and fixed services required")
	}
	if err := requireInstallJournal(files, j); err != nil {
		return j, err
	}
	for _, step := range []struct{ phase, name, next string }{
		{"prepared", ServiceName, "main_deleted"},
		{"main_deleted", RecoveryServiceName, "recovery_deleted"},
	} {
		if j.Phase != step.phase {
			continue
		}
		if err := services.Remove(step.name); err != nil {
			return j, err
		}
		next := j
		next.Phase = step.next
		if err := writeInstallJournal(files, next); err != nil {
			return j, err
		}
		j = next
	}
	for _, name := range []string{ServiceName, RecoveryServiceName} {
		if err := services.Absent(name); err != nil {
			return j, err
		}
	}
	if j.Phase == "recovery_deleted" {
		next := j
		next.Phase = "complete"
		if err := writeInstallJournal(files, next); err != nil {
			return j, err
		}
		j = next
	}
	return j, nil
}
