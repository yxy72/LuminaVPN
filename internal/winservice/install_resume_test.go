package winservice

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestResumeInstallPreflightNonpendingNeverLoadsInstalledRelease(t *testing.T) {
	for _, state := range []string{"first_install_missing_root", "old_release_complete", "old_release_retirement_pending"} {
		t.Run(state, func(t *testing.T) {
			files, j := journalFixture()
			exists := state != "first_install_missing_root"
			j.Image, j.ReleaseDigest = "old-installed-release/lumina-service.exe", strings.Repeat("b", 64)
			if state == "old_release_complete" {
				j = provisionedJournal(j)
				j.Phase = "complete"
			} else if exists {
				j.Action, j.Target.LastRestorationID = "retire", "restore-strict"
				j.Phase = "main_deleted"
			}
			locked, releases, factoryCalls := false, 0, 0
			var order []string
			result, err := resumeInstallPreflight(context.Background(), resumeInstallPreflightControl{
				acquire: func() (func(), error) {
					order, locked = append(order, "lock"), true
					return func() { order = append(order, "unlock"); locked = false; releases++ }, nil
				},
				journal: func() (installJournal, bool, error) {
					if !locked {
						t.Fatal("journal observed without installer lock")
					}
					order = append(order, "journal")
					return j, exists, nil
				},
				pending: func(context.Context, installJournal) (InstallSystem, error) {
					factoryCalls++
					return nil, errors.New("nonpending path must not load installation or write files")
				},
			})
			if err != nil || !result.Completed || result.Action != "resume-install-preflight" || locked || releases != 1 || factoryCalls != 0 || len(files.files) != 0 || !reflect.DeepEqual(order, []string{"lock", "journal", "unlock"}) {
				t.Fatal("nonpending preflight was not a read-only no-op", result, err, order, factoryCalls)
			}
		})
	}
}

func TestResumeInstallPreflightUnknownStateFailsBeforeFactoryAndReleasesLock(t *testing.T) {
	for _, failure := range []string{"read_unknown", "partial_read", "schema", "phase"} {
		t.Run(failure, func(t *testing.T) {
			_, j := journalFixture()
			var readErr error
			if failure == "read_unknown" || failure == "partial_read" {
				readErr = errors.New(failure)
			} else if failure == "schema" {
				j.Version++
			} else {
				j.Phase = "unknown"
			}
			locked, releases, factoryCalls := false, 0, 0
			result, err := resumeInstallPreflight(context.Background(), resumeInstallPreflightControl{
				acquire: func() (func(), error) {
					locked = true
					return func() { locked = false; releases++ }, nil
				},
				journal: func() (installJournal, bool, error) {
					if !locked {
						t.Fatal("unlocked journal observation")
					}
					return j, failure != "read_unknown", readErr
				},
				pending: func(context.Context, installJournal) (InstallSystem, error) {
					factoryCalls++
					return nil, nil
				},
			})
			if err == nil || result.Completed || locked || releases != 1 || factoryCalls != 0 {
				t.Fatal("unknown state reached installation or leaked lock", result, err, factoryCalls, releases)
			}
			if readErr != nil && !errors.Is(err, readErr) {
				t.Fatal("journal read error was lost", err)
			}
		})
	}
}

type resumeLockedInstallFixture struct {
	committingInstallFixture
	t            *testing.T
	locked       *bool
	order        *[]string
	configureErr error
}

func (f *resumeLockedInstallFixture) note(step string) {
	f.t.Helper()
	if !*f.locked {
		f.t.Fatalf("installer lock released before %s", step)
	}
	*f.order = append(*f.order, step)
}
func (f *resumeLockedInstallFixture) Inspect() (BootstrapState, error) {
	f.note("inspect")
	return f.installFixture.Inspect()
}
func (f *resumeLockedInstallFixture) Enrollment() (Binding, error) {
	f.note("enroll")
	return f.installFixture.Enrollment()
}
func (f *resumeLockedInstallFixture) ConfigureServices() error {
	f.note("configure")
	if err := f.installFixture.ConfigureServices(); err != nil {
		return err
	}
	return f.configureErr
}
func (f *resumeLockedInstallFixture) Provision(binding Binding) error {
	f.note("provision")
	return f.installFixture.Provision(binding)
}
func (f *resumeLockedInstallFixture) StartMain(ctx context.Context) error {
	f.note("start")
	return f.installFixture.StartMain(ctx)
}
func (f *resumeLockedInstallFixture) CommitBootstrap() error {
	f.note("commit")
	return f.committingInstallFixture.CommitBootstrap()
}

func TestResumeInstallPreflightKeepsOneLockThroughBootstrapAndCommit(t *testing.T) {
	for _, failure := range []string{"none", "configure", "provision", "commit", "factory", "nil_system"} {
		t.Run(failure, func(t *testing.T) {
			_, j := journalFixture()
			locked, releases := false, 0
			var order []string
			fixture := &resumeLockedInstallFixture{t: t, locked: &locked, order: &order, committingInstallFixture: committingInstallFixture{installFixture: installFixture{state: BootstrapState{Present: true, Trusted: true, Enrolled: true, BootstrapPending: true}}}}
			injected := errors.New("interrupted " + failure)
			switch failure {
			case "configure":
				fixture.configureErr = injected
			case "provision":
				fixture.provisionErr = injected
			case "commit":
				fixture.commitErr = injected
			}
			ctx := context.WithValue(context.Background(), struct{}{}, "same-context")
			result, err := resumeInstallPreflight(ctx, resumeInstallPreflightControl{
				acquire: func() (func(), error) {
					order, locked = append(order, "lock"), true
					return func() { order = append(order, "unlock"); locked = false; releases++ }, nil
				},
				journal: func() (installJournal, bool, error) {
					if !locked {
						t.Fatal("journal observed without lock")
					}
					order = append(order, "journal")
					return j, true, nil
				},
				pending: func(observedContext context.Context, observed installJournal) (InstallSystem, error) {
					if !locked || observedContext != ctx || !sameInstallJournalPlan(observed, j) || observed.Phase != j.Phase {
						t.Fatal("factory did not receive the locked exact pending plan")
					}
					order = append(order, "factory")
					if failure == "factory" {
						return nil, injected
					}
					if failure == "nil_system" {
						return nil, nil
					}
					return fixture, nil
				},
			})
			want := []string{"lock", "journal", "factory", "inspect", "enroll", "configure", "provision", "start", "commit"}
			switch failure {
			case "factory", "nil_system":
				want = want[:3]
			case "configure":
				want = want[:6]
			case "provision":
				want = want[:7]
			}
			want = append(want, "unlock")
			if (err == nil) != (failure == "none") || result.Completed != (failure == "none") || result.Action != "resume-install-preflight" || locked || releases != 1 || !reflect.DeepEqual(order, want) {
				t.Fatal("pending preflight skipped order, released early, or acknowledged failure", result, err, order, want)
			}
			if failure != "none" && failure != "nil_system" && !errors.Is(err, injected) {
				t.Fatal("original failure was lost", err)
			}
		})
	}
}

func TestResumeInstallPreflightDoesNotReadWithoutLockOrAfterCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if canceled {
			cancel()
		}
		acquired, read, factory := 0, 0, 0
		result, err := resumeInstallPreflight(ctx, resumeInstallPreflightControl{
			acquire: func() (func(), error) { acquired++; return nil, errors.New("lock unavailable") },
			journal: func() (installJournal, bool, error) { read++; return installJournal{}, false, nil },
			pending: func(context.Context, installJournal) (InstallSystem, error) { factory++; return nil, nil },
		})
		cancel()
		if err == nil || result.Completed || read != 0 || factory != 0 || canceled && acquired != 0 || !canceled && acquired != 1 {
			t.Fatal("unlocked or canceled preflight read state", result, err, acquired, read, factory)
		}
	}
}

func TestResumeInstallPreflightCancellationStopsBeforeOrAfterFactory(t *testing.T) {
	for _, point := range []string{"before_factory", "after_factory"} {
		t.Run(point, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_, j := journalFixture()
			locked, releases := false, 0
			var order []string
			fixture := &resumeLockedInstallFixture{t: t, locked: &locked, order: &order}
			result, err := resumeInstallPreflight(ctx, resumeInstallPreflightControl{
				acquire: func() (func(), error) {
					order, locked = append(order, "lock"), true
					return func() { order = append(order, "unlock"); locked = false; releases++ }, nil
				},
				journal: func() (installJournal, bool, error) {
					if !locked {
						t.Fatal("unlocked cancellation checkpoint")
					}
					order = append(order, "journal")
					if point == "before_factory" {
						cancel()
					}
					return j, true, nil
				},
				pending: func(context.Context, installJournal) (InstallSystem, error) {
					if !locked {
						t.Fatal("factory lost installer lock")
					}
					order = append(order, "factory")
					cancel()
					return fixture, nil
				},
			})
			want := []string{"lock", "journal"}
			if point == "after_factory" {
				want = append(want, "factory")
			}
			want = append(want, "unlock")
			if !errors.Is(err, context.Canceled) || result.Completed || locked || releases != 1 || len(fixture.calls) != 0 || !reflect.DeepEqual(order, want) {
				t.Fatal("canceled factory boundary reached Bootstrap or leaked lock", result, err, order, fixture.calls)
			}
		})
	}
}

func TestPendingResumeRequiresPinnedReleaseHelperAndOriginalFullLogin(t *testing.T) {
	_, j := journalFixture()
	evidence := resumeInstallerEvidence{Image: j.Image, ReleaseDigest: j.ReleaseDigest, HelperSHA256: strings.Repeat("c", 64), ServiceSHA256: strings.Repeat("c", 64), Enrollment: j.Target}
	evidence.Enrollment.ServiceInstance = ""
	if err := verifyPendingResume(j, evidence); err != nil {
		t.Fatal("original independently verified release/login rejected", err)
	}
	for name, mutate := range map[string]func(*resumeInstallerEvidence){
		"image":        func(e *resumeInstallerEvidence) { e.Image += ".foreign" },
		"release":      func(e *resumeInstallerEvidence) { e.ReleaseDigest = strings.Repeat("d", 64) },
		"helper":       func(e *resumeInstallerEvidence) { e.HelperSHA256 = strings.Repeat("d", 64) },
		"helper_hash":  func(e *resumeInstallerEvidence) { e.HelperSHA256 = "invalid" },
		"service_hash": func(e *resumeInstallerEvidence) { e.ServiceSHA256 = "invalid" },
		"owner":        func(e *resumeInstallerEvidence) { e.Enrollment.OwnerSID = "S-1-5-21-99" },
		"logon":        func(e *resumeInstallerEvidence) { e.Enrollment.LogonSID = "S-1-5-5-2-2" },
		"auth":         func(e *resumeInstallerEvidence) { e.Enrollment.AuthenticationID = "later-auth" },
		"session":      func(e *resumeInstallerEvidence) { e.Enrollment.SessionID++ },
		"epoch":        func(e *resumeInstallerEvidence) { e.Enrollment.LogonEpoch = "later-epoch" },
		"profile":      func(e *resumeInstallerEvidence) { e.Enrollment.ProfileID = "other" },
		"executor":     func(e *resumeInstallerEvidence) { e.Enrollment.ExecutorSID = "S-1-5-19" },
	} {
		t.Run(name, func(t *testing.T) {
			foreign := evidence
			mutate(&foreign)
			if err := verifyPendingResume(j, foreign); err == nil {
				t.Fatal("foreign release/helper/login accepted")
			}
		})
	}
	for _, change := range []func(*installJournal){
		func(j *installJournal) { j.Version++ },
		func(j *installJournal) { *j = provisionedJournal(*j); j.Phase = "complete" },
		func(j *installJournal) { j.Action = "retire"; j.Target.LastRestorationID = "restore-strict" },
	} {
		invalid := j
		change(&invalid)
		if err := verifyPendingResume(invalid, evidence); err == nil {
			t.Fatal("nonpending or invalid plan accepted")
		}
	}
}

func TestResumeBootstrapNoncePathAllowsOnlyFixedNativeSetupLocation(t *testing.T) {
	base := t.TempDir()
	programData := filepath.Join(base, "ProgramData")
	nonce := strings.Repeat("a", 32)
	valid := filepath.Join(programData, "LuminaVPN-Setup", nonce, "lumina-service.exe")
	if !resumeBootstrapNoncePath(valid, programData) {
		t.Fatal("fixed native setup nonce path rejected")
	}
	for _, path := range []string{
		filepath.Join(base, "Program Files", "LuminaVPN", "lumina-service.exe"),
		filepath.Join(programData, "LuminaVPN-Setup", "bad-nonce", "lumina-service.exe"),
		filepath.Join(programData, "LuminaVPN-Setup", strings.Repeat("A", 32), "lumina-service.exe"),
		filepath.Join(programData, "LuminaVPN-Setup", strings.Repeat("g", 32), "lumina-service.exe"),
		filepath.Join(programData, "LuminaVPN-Setup", nonce, "other.exe"),
		filepath.Join(programData, "Other-Setup", nonce, "lumina-service.exe"),
		filepath.Join("relative", "LuminaVPN-Setup", nonce, "lumina-service.exe"),
		filepath.Dir(valid) + string(filepath.Separator) + ".." + string(filepath.Separator) + nonce + string(filepath.Separator) + "lumina-service.exe",
	} {
		if resumeBootstrapNoncePath(path, programData) {
			t.Fatal("fallback, relative, unclean or invalid nonce path accepted", path)
		}
	}
}
