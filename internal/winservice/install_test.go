package winservice

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type installFixture struct {
	state        BootstrapState
	calls        []string
	recoverErr   error
	stillRunning bool
}

func (f *installFixture) Inspect() (BootstrapState, error) {
	f.calls = append(f.calls, "inspect")
	return f.state, nil
}
func (f *installFixture) Enrollment() (Binding, error) {
	f.calls = append(f.calls, "enroll")
	return Binding{ProfileID: "profile"}, nil
}
func (f *installFixture) Provision(Binding) error { f.calls = append(f.calls, "provision"); return nil }
func (f *installFixture) ConfigureServices() error {
	f.calls = append(f.calls, "configure")
	return nil
}
func (f *installFixture) StartMain(context.Context) error {
	f.calls = append(f.calls, "start")
	return nil
}
func (f *installFixture) StopMain(context.Context) error {
	f.calls = append(f.calls, "stop")
	return errors.New("crashed main")
}
func (f *installFixture) MainStopped() (bool, error) {
	f.calls = append(f.calls, "quiescent")
	return !f.stillRunning, nil
}
func (f *installFixture) RecoverExact(context.Context) error {
	f.calls = append(f.calls, "recover")
	return f.recoverErr
}
func (f *installFixture) DeleteServices() error {
	f.calls = append(f.calls, "delete_services")
	return nil
}
func TestBootstrapPreservesUnknownExistingState(t *testing.T) {
	fixture := &installFixture{state: BootstrapState{Present: true}}
	if _, err := Bootstrap(context.Background(), fixture); err == nil || !reflect.DeepEqual(fixture.calls, []string{"inspect"}) {
		t.Fatal("unknown state was overwritten")
	}
}
func TestUninstallRequiresExactRecoveryBeforeDeletingSCM(t *testing.T) {
	for _, fail := range []bool{false, true} {
		fixture := &installFixture{state: BootstrapState{Present: true, Trusted: true, Enrolled: true, ServicesMatch: true}}
		if fail {
			fixture.recoverErr = errors.New("proof incomplete")
		}
		result, err := Uninstall(context.Background(), fixture)
		if fail {
			if err == nil || result.Completed || result.Restored || !reflect.DeepEqual(fixture.calls, []string{"inspect", "stop", "quiescent", "recover"}) {
				t.Fatal("failed recovery permitted uninstall")
			}
		} else {
			if err != nil || !result.Completed || !result.Restored || !reflect.DeepEqual(fixture.calls, []string{"inspect", "stop", "quiescent", "recover", "delete_services"}) {
				t.Fatal("recovery did not precede deletion")
			}
		}
	}
}
func TestUninstallDoesNotRecoverAcrossAStillRunningMainService(t *testing.T) {
	fixture := &installFixture{state: BootstrapState{Present: true, Trusted: true, Enrolled: true, ServicesMatch: true}, stillRunning: true}
	if _, err := Uninstall(context.Background(), fixture); err == nil || !reflect.DeepEqual(fixture.calls, []string{"inspect", "stop", "quiescent"}) {
		t.Fatal("unknown/still-running main entered recovery")
	}
}
func TestEnrollmentPersistsLimitedShellIdentityNotElevatedAuthID(t *testing.T) {
	linked := EnrollmentFacts{SID: "S-1-5-21-1", LogonSID: "S-1-5-5-1-1", AuthenticationID: "limited-auth", SessionID: 1, Primary: true, Limited: true, LogonEpoch: "epoch-1", Interactive: true}
	shell := linked
	full := linked
	full.AuthenticationID = "full-auth"
	full.Elevated = true
	full.Limited = false
	binding, err := verifiedEnrollment(full, linked, shell, "profile")
	if err != nil || binding.AuthenticationID != "limited-auth" {
		t.Fatal("fulltoken identity leaked into GUI enrollment")
	}
	for _, alter := range []func(*EnrollmentFacts){func(f *EnrollmentFacts) { f.AuthenticationID = "other" }, func(f *EnrollmentFacts) { f.LogonSID = "S-1-5-5-1-2" }, func(f *EnrollmentFacts) { f.SID = "S-1-5-21-2" }, func(f *EnrollmentFacts) { f.SessionID = 2 }, func(f *EnrollmentFacts) { f.Elevated = true; f.Limited = false }, func(f *EnrollmentFacts) { f.Primary = false }} {
		bad := linked
		alter(&bad)
		if _, err := verifiedEnrollment(full, bad, shell, "profile"); err == nil {
			t.Fatal("mismatched/full/foreign token enrolled")
		}
	}
}
func TestInstallerCommandHasNoPathOrShellAuthority(t *testing.T) {
	for _, args := range [][]string{{"--bootstrap", "C:\\user.exe"}, {"--recover-service", "--run", "foreign"}, {"powershell"}, nil} {
		if _, err := ParseCommand(args); err == nil {
			t.Fatal("unbounded entry accepted")
		}
	}
}
func TestInstallerElevationRejectsDisabledAndDenyOnlyAdminGroups(t *testing.T) {
	if !installerAdministrator("S-1-5-18", false, false, false) {
		t.Fatal("SYSTEM recovery requester was rejected")
	}
	for _, facts := range [][3]bool{{false, true, false}, {true, false, false}, {true, true, true}} {
		if installerAdministrator("S-1-5-21-1", facts[0], facts[1], facts[2]) {
			t.Fatal("unprivileged installer context accepted")
		}
	}
}
