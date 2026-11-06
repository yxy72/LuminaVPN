//go:build windows

package app

import (
	"errors"
	"testing"

	"netlaunch/internal/winservice"
)

func TestRecoveryHelperExitGatePreservesMainBrokerAndReadOnlyStatus(t *testing.T) {
	for _, action := range []winservice.LifecycleAction{winservice.RecoverLifecycle, winservice.AbortPrepareLifecycle} {
		if err := serviceHelperRecoveryExitGate(action, func() error { return nil }, func() error { t.Fatal("live main broker required to exit"); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if err := serviceHelperRecoveryExitGate(winservice.StatusLifecycle, func() error { t.Fatal("status exit gate queried role"); return nil }, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryHelperExitGateRequiresSeparateConfirmedExit(t *testing.T) {
	for _, action := range []winservice.LifecycleAction{winservice.RecoverLifecycle, winservice.AbortPrepareLifecycle} {
		calls := 0
		exitErr := errors.New("original host still alive or unknown")
		if err := serviceHelperRecoveryExitGate(action, func() error { return errMainServiceHelperSIDAbsent }, func() error { calls++; return exitErr }); !errors.Is(err, exitErr) || calls != 1 {
			t.Fatal("exit uncertainty swallowed", err, calls)
		}
		if err := serviceHelperRecoveryExitGate(action, func() error { return errMainServiceHelperSIDAbsent }, nil); err == nil {
			t.Fatal("missing exit proof accepted")
		}
		if err := serviceHelperRecoveryExitGate(action, func() error { return errMainServiceHelperSIDAbsent }, func() error { return nil }); err != nil {
			t.Fatal("confirmed old owner exit rejected", err)
		}
		for _, roleErr := range []error{errors.New("token query access denied"), errors.New("main SID deny-only")} {
			if err := serviceHelperRecoveryExitGate(action, func() error { return roleErr }, func() error { t.Fatal("unknown role selected recovery"); return nil }); !errors.Is(err, roleErr) {
				t.Fatal("role error became death proof", err)
			}
		}
	}
}

func TestRecoveryQuiescenceRequiresCurrentSCMStoppedBeforeOriginalPIDProof(t *testing.T) {
	unknown := errors.New("current main SCM status unknown or running")
	if err := serviceHelperRecoveryQuiescence(func() error { return unknown }, func() error { t.Fatal("original PID death bypassed current main SCM gate"); return nil }); !errors.Is(err, unknown) {
		t.Fatal("SCM observation failure swallowed", err)
	}
	steps := 0
	if err := serviceHelperRecoveryQuiescence(func() error { steps++; return nil }, func() error {
		if steps != 1 {
			t.Fatal("original process queried before SCM stopped")
		}
		steps++
		return nil
	}); err != nil || steps != 2 {
		t.Fatal("independent proof order differs", err, steps)
	}
}
