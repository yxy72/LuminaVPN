package winservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func journalFixture() (*memoryStateFiles, installJournal) {
	target := testBinding("profile")
	target.LogonEpoch = "current-epoch"
	target.Revision = 1
	return &memoryStateFiles{files: map[string][]byte{}}, installJournal{Version: 1, Action: "bootstrap", Phase: "prepared", ReleaseDigest: strings.Repeat("a", 64), Image: `C:\Program Files\LuminaVPN\lumina-service.exe`, Target: target}
}

func provisionedJournal(j installJournal) installJournal {
	j.Phase = "provisioned"
	publication := j.Target
	if j.Previous != nil && !sameEnrollment(*j.Previous, j.Target) {
		publication.LastRestorationID = "restore-new"
	}
	j.Published = &publication
	return j
}

func TestInstallJournalValidBootstrapAndRetirementProgress(t *testing.T) {
	for _, retired := range []bool{false, true} {
		files, j := journalFixture()
		if retired {
			previous := j.Target
			previous.Revision = 8
			previous.LastRestorationID = "restore-old"
			j.Previous = &previous
			j.Target = previous
			j.Target.Revision++
			j.Target.LogonSID, j.Target.AuthenticationID, j.Target.LogonEpoch = "S-1-5-5-2-2", "new-auth", "new-epoch"
		}
		if err := beginInstallJournal(files, j); err != nil {
			t.Fatal(err)
		}
		j.Phase = "services_ready"
		if err := writeInstallJournal(files, j); err != nil {
			t.Fatal(err)
		}
		j = provisionedJournal(j)
		if err := writeInstallJournal(files, j); err != nil {
			t.Fatal(err)
		}
		j.Phase = "complete"
		if err := writeInstallJournal(files, j); err != nil {
			t.Fatal(err)
		}
		observed, exists, err := readInstallJournal(files)
		if err != nil || !exists || !sameInstallJournalPlan(observed, j) || observed.Published == nil || *observed.Published != *j.Published {
			t.Fatal("completed frozen provisioning was not retained", observed, exists, err)
		}
		retire := installJournal{Version: 1, Action: "retire", Phase: "prepared", ReleaseDigest: j.ReleaseDigest, Image: j.Image, Target: *j.Published}
		retire.Target.LastRestorationID = "restore-strict"
		if err = beginInstallJournal(files, retire); err != nil {
			t.Fatal(err)
		}
		for _, phase := range []string{"main_deleted", "recovery_deleted", "complete"} {
			retire.Phase = phase
			if err = writeInstallJournal(files, retire); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestInstallJournalRejectsInvalidPlanOrPublication(t *testing.T) {
	for name, mutate := range map[string]func(*installJournal){
		"version":                func(j *installJournal) { j.Version++ },
		"action":                 func(j *installJournal) { j.Action = "execute" },
		"phase":                  func(j *installJournal) { j.Phase = "started" },
		"digest":                 func(j *installJournal) { j.ReleaseDigest = "not-a-digest" },
		"image_empty":            func(j *installJournal) { j.Image = "" },
		"image_nul":              func(j *installJournal) { j.Image += "\x00--execute" },
		"profile":                func(j *installJournal) { j.Target.ProfileID = "../other" },
		"owner":                  func(j *installJournal) { j.Target.OwnerSID = "invalid" },
		"system_owner":           func(j *installJournal) { j.Target.OwnerSID = "S-1-5-18" },
		"logon":                  func(j *installJournal) { j.Target.LogonSID = "invalid" },
		"executor":               func(j *installJournal) { j.Target.ExecutorSID = "S-1-5-19" },
		"instance":               func(j *installJournal) { j.Target.ServiceInstance = "../other" },
		"session":                func(j *installJournal) { j.Target.SessionID = 0 },
		"auth":                   func(j *installJournal) { j.Target.AuthenticationID = "" },
		"fresh_revision":         func(j *installJournal) { j.Target.Revision = 2 },
		"fresh_receipt":          func(j *installJournal) { j.Target.LastRestorationID = "restore-unproved" },
		"missing_epoch":          func(j *installJournal) { j.Target.LogonEpoch = "" },
		"run":                    func(j *installJournal) { j.Target.RunRef = "still-active" },
		"pending":                func(j *installJournal) { j.Target.PendingEnrollmentID = "pending" },
		"early_publication":      func(j *installJournal) { b := j.Target; j.Published = &b },
		"missing_publication":    func(j *installJournal) { j.Phase = "provisioned" },
		"foreign_publication":    func(j *installJournal) { *j = provisionedJournal(*j); j.Published.SessionID++ },
		"publication_revision":   func(j *installJournal) { *j = provisionedJournal(*j); j.Published.Revision++ },
		"retire_without_receipt": func(j *installJournal) { j.Action = "retire" },
		"retire_with_previous": func(j *installJournal) {
			j.Action = "retire"
			j.Target.LastRestorationID = "restore-old"
			b := j.Target
			j.Previous = &b
		},
		"retire_with_publication": func(j *installJournal) {
			j.Action = "retire"
			j.Target.LastRestorationID = "restore-old"
			b := j.Target
			j.Published = &b
		},
	} {
		t.Run(name, func(t *testing.T) {
			files, j := journalFixture()
			mutate(&j)
			if validateInstallJournal(j) == nil {
				t.Fatal("invalid journal passed schema validation")
			}
			if err := writeInstallJournal(files, j); err == nil || len(files.files) != 0 {
				t.Fatal("invalid journal was published", err)
			}
		})
	}
}

func TestInstallJournalRetiredPlanRequiresExactRevisionAndNewLoginReceipt(t *testing.T) {
	for name, mutate := range map[string]func(*installJournal){
		"foreign_previous":         func(j *installJournal) { j.Previous.OwnerSID = "S-1-5-21-99" },
		"missing_previous_receipt": func(j *installJournal) { j.Previous.LastRestorationID = "" },
		"active_previous":          func(j *installJournal) { j.Previous.RunRef = "active" },
		"pending_previous":         func(j *installJournal) { j.Previous.PendingEnrollmentID = "pending" },
		"overflow":                 func(j *installJournal) { j.Previous.Revision = ^uint64(0); j.Target.Revision = 1 },
		"skipped_revision":         func(j *installJournal) { j.Target.Revision++ },
		"target_receipt_drift":     func(j *installJournal) { j.Target.LastRestorationID = "restore-unplanned" },
		"new_login_old_receipt": func(j *installJournal) {
			*j = provisionedJournal(*j)
			j.Published.LastRestorationID = j.Previous.LastRestorationID
		},
		"same_login_changed_receipt": func(j *installJournal) {
			j.Target = *j.Previous
			j.Target.Revision++
			*j = provisionedJournal(*j)
			j.Published.LastRestorationID = "restore-unplanned"
		},
	} {
		t.Run(name, func(t *testing.T) {
			files, j := journalFixture()
			previous := j.Target
			previous.Revision, previous.LastRestorationID = 9, "restore-old"
			j.Previous = &previous
			j.Target = previous
			j.Target.Revision++
			j.Target.LogonEpoch = "new-epoch"
			mutate(&j)
			if validateInstallJournal(j) == nil {
				t.Fatal("invalid journal passed schema validation")
			}
			if err := writeInstallJournal(files, j); err == nil || len(files.files) != 0 {
				t.Fatal("invalid retired journal was published", err)
			}
		})
	}
}

type journalReadFailure struct{ err error }

func (f journalReadFailure) Read(string) ([]byte, error) { return nil, f.err }
func (f journalReadFailure) Write(string, []byte) error  { return errors.New("unexpected write") }

func TestInstallJournalReadDoesNotTreatUnknownOrUnreadableAsAbsent(t *testing.T) {
	files, j := journalFixture()
	if _, exists, err := readInstallJournal(files); err != nil || exists {
		t.Fatal("missing sentinel was not absence", exists, err)
	}
	for _, failure := range []error{errors.New("access denied"), errors.New("not found text is not the missing sentinel")} {
		if _, exists, err := readInstallJournal(journalReadFailure{failure}); !exists || !errors.Is(err, failure) {
			t.Fatal("read failure became absent", exists, err)
		}
	}
	valid, _ := json.Marshal(j)
	for _, data := range [][]byte{[]byte("null"), []byte("{"), append(valid[:len(valid)-1:len(valid)-1], []byte(`,"unknown":true}`)...), append(append([]byte{}, valid...), []byte(" {}")...)} {
		files.files[installJournalPath] = data
		before := string(data)
		if _, exists, err := readInstallJournal(files); !exists || err == nil {
			t.Fatal("unknown journal became absent", exists, err)
		}
		if err := beginInstallJournal(files, j); err == nil || string(files.files[installJournalPath]) != before {
			t.Fatal("unknown journal was replaced", err)
		}
	}
}

func TestInstallJournalWriteRejectsDriftRegressionAndPublicationChange(t *testing.T) {
	for name, mutate := range map[string]func(*installJournal){
		"release":    func(j *installJournal) { j.ReleaseDigest = strings.Repeat("b", 64) },
		"image":      func(j *installJournal) { j.Image += ".other" },
		"identity":   func(j *installJournal) { j.Target.LogonEpoch = "other-login" },
		"regression": func(j *installJournal) { j.Phase = "prepared" },
	} {
		t.Run(name, func(t *testing.T) {
			files, j := journalFixture()
			if err := beginInstallJournal(files, j); err != nil {
				t.Fatal(err)
			}
			j.Phase = "services_ready"
			if err := writeInstallJournal(files, j); err != nil {
				t.Fatal(err)
			}
			before := string(files.files[installJournalPath])
			mutate(&j)
			if err := writeInstallJournal(files, j); err == nil || string(files.files[installJournalPath]) != before {
				t.Fatal("drift or regression replaced journal", err)
			}
		})
	}
	files, j := journalFixture()
	previous := j.Target
	previous.Revision, previous.LastRestorationID = 4, "restore-old"
	j.Previous = &previous
	j.Target = previous
	j.Target.Revision++
	j.Target.LogonEpoch = "new-epoch"
	if err := beginInstallJournal(files, j); err != nil {
		t.Fatal(err)
	}
	j = provisionedJournal(j)
	if err := writeInstallJournal(files, j); err != nil {
		t.Fatal(err)
	}
	before := string(files.files[installJournalPath])
	j.Phase = "complete"
	j.Published.LastRestorationID = "restore-drift"
	if err := validateInstallJournal(j); err != nil {
		t.Fatal("test must exercise immutable publication rather than invalid schema", err)
	}
	if err := writeInstallJournal(files, j); err == nil || string(files.files[installJournalPath]) != before {
		t.Fatal("published receipt was replaced", err)
	}
}

func TestInstallJournalBeginPreservesPendingAndAtomicFailure(t *testing.T) {
	files, j := journalFixture()
	if err := writeInstallJournal(files, j); err == nil || len(files.files) != 0 {
		t.Fatal("phase write manufactured an absent cycle", err)
	}
	if err := beginInstallJournal(files, j); err != nil {
		t.Fatal(err)
	}
	before := string(files.files[installJournalPath])
	if err := beginInstallJournal(files, j); err == nil || string(files.files[installJournalPath]) != before {
		t.Fatal("pending cycle was replaced", err)
	}
	j = provisionedJournal(j)
	j.Phase = "complete"
	if err := writeInstallJournal(files, j); err != nil {
		t.Fatal(err)
	}
	before = string(files.files[installJournalPath])
	_, next := journalFixture()
	next.ReleaseDigest = strings.Repeat("b", 64)
	files.failWrite = true
	if err := beginInstallJournal(files, next); err == nil || string(files.files[installJournalPath]) != before {
		t.Fatal("failed cycle publication discarded completed history", err)
	}
	files.failWrite = false
	if err := beginInstallJournal(files, next); err != nil {
		t.Fatal(err)
	}
	if observed, exists, err := readInstallJournal(files); err != nil || !exists || !sameInstallJournalPlan(observed, next) {
		t.Fatal("completed cycle could not be atomically replaced", err)
	}
	before = string(files.files[installJournalPath])
	next.Phase = "services_ready"
	files.failWrite = true
	if err := writeInstallJournal(files, next); err == nil || string(files.files[installJournalPath]) != before {
		t.Fatal("failed phase publication changed journal", err)
	}
}

func TestInstallJournalCallerUsesFullLoginTuple(t *testing.T) {
	_, j := journalFixture()
	captured := j.Target
	captured.ServiceInstance, captured.LastRestorationID = "", ""
	if !journalCallerMatches(j, captured) {
		t.Fatal("exact independently captured login did not match")
	}
	for _, mutate := range []func(*Binding){
		func(b *Binding) { b.OwnerSID = "S-1-5-21-99" },
		func(b *Binding) { b.LogonSID = "S-1-5-5-3-3" },
		func(b *Binding) { b.AuthenticationID = "other-auth" },
		func(b *Binding) { b.SessionID++ },
		func(b *Binding) { b.LogonEpoch = "other-epoch" },
		func(b *Binding) { b.ExecutorSID = "S-1-5-19" },
		func(b *Binding) { b.ProfileID = "other-profile" },
	} {
		other := captured
		mutate(&other)
		if journalCallerMatches(j, other) {
			t.Fatal("different captured identity matched")
		}
	}
	j.Action = "retire"
	j.Target.LastRestorationID = "restore-strict"
	if journalCallerMatches(j, captured) {
		t.Fatal("retirement accepted bootstrap caller check")
	}
}

type journalMockServices struct {
	present   map[string]bool
	foreign   map[string]bool
	calls     []string
	failAt    string
	failAfter bool
}

func mockJournalServices(installed bool) *journalMockServices {
	return &journalMockServices{present: map[string]bool{ServiceName: installed, RecoveryServiceName: installed}, foreign: map[string]bool{}}
}

func (s *journalMockServices) step(action, name string, mutate func()) error {
	key := action + ":" + name
	s.calls = append(s.calls, key)
	if name != ServiceName && name != RecoveryServiceName {
		return errors.New("unexpected generic service name")
	}
	if s.foreign[name] {
		return errors.New("foreign service configuration")
	}
	if s.failAt == key && !s.failAfter {
		return errors.New("SCM failed before observation or mutation")
	}
	if mutate != nil {
		mutate()
	}
	if s.failAt == key {
		return errors.New("SCM failed after observation or mutation")
	}
	return nil
}

func (s *journalMockServices) Ensure(name string, allowPartial bool) error {
	if !allowPartial {
		return errors.New("prepared retry did not permit verified partial SCM state")
	}
	return s.step("ensure", name, func() { s.present[name] = true })
}
func (s *journalMockServices) Verify(name string) error {
	if err := s.step("verify", name, nil); err != nil {
		return err
	}
	if !s.present[name] {
		return errors.New("service missing")
	}
	return nil
}
func (s *journalMockServices) Remove(name string) error {
	return s.step("remove", name, func() { s.present[name] = false })
}
func (s *journalMockServices) Absent(name string) error {
	if err := s.step("absent", name, nil); err != nil {
		return err
	}
	if s.present[name] {
		return errors.New("service unexpectedly present")
	}
	return nil
}

func retireJournalFixture() (*memoryStateFiles, installJournal) {
	files, j := journalFixture()
	j.Action = "retire"
	j.Target.LastRestorationID = "restore-strict"
	return files, j
}

func TestInstallJournalBootstrapSCMInterruptionsResumeOnlyPreparedCreation(t *testing.T) {
	for _, step := range []string{"ensure:" + ServiceName, "ensure:" + RecoveryServiceName, "verify:" + ServiceName, "verify:" + RecoveryServiceName} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/after=%t", step, after), func(t *testing.T) {
				files, j := journalFixture()
				if err := beginInstallJournal(files, j); err != nil {
					t.Fatal(err)
				}
				services := mockJournalServices(false)
				services.failAt, services.failAfter = step, after
				pending, err := resumeBootstrapServices(files, j, services)
				if err == nil || pending.Phase != "prepared" {
					t.Fatal("failed partial creation advanced the journal", pending, err)
				}
				services.failAt = ""
				ready, err := resumeBootstrapServices(files, pending, services)
				if err != nil || ready.Phase != "services_ready" || !services.present[ServiceName] || !services.present[RecoveryServiceName] {
					t.Fatal("verified partial creation did not resume", ready, err)
				}
				services.calls = nil
				services.present[ServiceName] = false
				if _, err = resumeBootstrapServices(files, ready, services); err == nil {
					t.Fatal("missing service after prepared was recreated")
				}
				for _, call := range services.calls {
					if strings.HasPrefix(call, "ensure:") {
						t.Fatal("nonprepared bootstrap created a service", services.calls)
					}
				}
			})
		}
	}
}

func TestInstallJournalRetirementSCMInterruptionsResumeExactDeletion(t *testing.T) {
	for _, step := range []string{"remove:" + ServiceName, "remove:" + RecoveryServiceName, "absent:" + ServiceName, "absent:" + RecoveryServiceName} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/after=%t", step, after), func(t *testing.T) {
				files, j := retireJournalFixture()
				if err := beginInstallJournal(files, j); err != nil {
					t.Fatal(err)
				}
				services := mockJournalServices(true)
				services.failAt, services.failAfter = step, after
				pending, err := resumeRetirementServices(files, j, services)
				if err == nil || pending.Phase == "complete" {
					t.Fatal("unconfirmed deletion completed the journal", pending, err)
				}
				durable, _, readErr := readInstallJournal(files)
				if readErr != nil || durable.Phase != pending.Phase {
					t.Fatal("returned phase was not the last durable phase", pending, durable, readErr)
				}
				services.failAt = ""
				complete, err := resumeRetirementServices(files, pending, services)
				if err != nil || complete.Phase != "complete" || services.present[ServiceName] || services.present[RecoveryServiceName] {
					t.Fatal("partial deletion did not resume", complete, err)
				}
				services.calls = nil
				services.present[ServiceName] = true
				if _, err = resumeRetirementServices(files, complete, services); err == nil || !services.present[ServiceName] {
					t.Fatal("completed journal deleted a reappearing service", services.calls, err)
				}
				for _, call := range services.calls {
					if strings.HasPrefix(call, "remove:") {
						t.Fatal("completed retirement repeated deletion", services.calls)
					}
				}
			})
		}
	}
}

type journalWriteFailure struct {
	*memoryStateFiles
	writes, failAt int
}

func (f *journalWriteFailure) Write(path string, data []byte) error {
	f.writes++
	if f.writes == f.failAt {
		return errors.New("interrupted atomic journal publication")
	}
	return f.memoryStateFiles.Write(path, data)
}

func TestInstallJournalSCMProgressWriteFailuresKeepDurableRetryPhase(t *testing.T) {
	for _, retire := range []bool{false, true} {
		lastWrite := 2
		if retire {
			lastWrite = 4
		}
		for failAt := 2; failAt <= lastWrite; failAt++ {
			t.Run(fmt.Sprintf("retire=%t/write=%d", retire, failAt), func(t *testing.T) {
				base, j := journalFixture()
				if retire {
					base, j = retireJournalFixture()
				}
				files := &journalWriteFailure{memoryStateFiles: base, failAt: failAt}
				if err := beginInstallJournal(files, j); err != nil {
					t.Fatal(err)
				}
				services := mockJournalServices(retire)
				resume := resumeBootstrapServices
				want := "services_ready"
				if retire {
					resume, want = resumeRetirementServices, "complete"
				}
				pending, err := resume(files, j, services)
				if err == nil {
					t.Fatal("failed phase publication was acknowledged")
				}
				durable, _, readErr := readInstallJournal(files)
				if readErr != nil || durable.Phase != pending.Phase {
					t.Fatal("publication failure lost last durable phase", durable, pending, readErr)
				}
				files.failAt = 0
				completed, err := resume(files, durable, services)
				if err != nil || completed.Phase != want {
					t.Fatal("SCM side effect could not resume after journal write failure", completed, err)
				}
			})
		}
	}
}

func TestInstallJournalSCMRejectsMissingStaleAndForeignPlans(t *testing.T) {
	for _, retire := range []bool{false, true} {
		files, j := journalFixture()
		resume := resumeBootstrapServices
		if retire {
			files, j = retireJournalFixture()
			resume = resumeRetirementServices
		}
		services := mockJournalServices(retire)
		if _, err := resume(files, j, services); err == nil || len(services.calls) != 0 {
			t.Fatal("SCM mutation ran without a durable prepared journal", err)
		}
		if err := beginInstallJournal(files, j); err != nil {
			t.Fatal(err)
		}
		stale := j
		stale.Target.LogonEpoch = "unpublished-login"
		if _, err := resume(files, stale, services); err == nil || len(services.calls) != 0 {
			t.Fatal("unpublished plan reached SCM", err)
		}
		services.foreign[ServiceName] = true
		before := string(files.files[installJournalPath])
		if _, err := resume(files, j, services); err == nil || len(services.calls) != 1 || string(files.files[installJournalPath]) != before {
			t.Fatal("foreign service was ignored or later SCM step ran", services.calls, err)
		}
	}
}
