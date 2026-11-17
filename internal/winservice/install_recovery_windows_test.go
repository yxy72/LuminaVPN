//go:build windows

package winservice

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

func TestRecoveryResultRejectsTerminalFailureWithoutWaitingForAcknowledgement(t *testing.T) {
	files, binding := fixtureStateFiles(t)
	got, err := waitForRecoveryResult(t.Context(), func() (svc.Status, error) {
		return svc.Status{State: svc.Stopped, Win32ExitCode: uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR), ServiceSpecificExitCode: recoveryExitProof}, nil
	}, files, binding.ProfileID, "recover-new")
	if got != (Binding{}) || RecoveryCommandDiagnostic(err) != "Windows recovery service failed (stage=restoration_proof, win32=1066, service=216)" {
		t.Fatalf("unexpected recovery outcome: %v", err)
	}
	if RecoveryCommandDiagnostic(errors.New("private file path")) != "" {
		t.Fatal("a raw failure could escape the recovery command")
	}
}

func TestRecoveryResultRequiresCurrentAcknowledgementAfterServiceStops(t *testing.T) {
	files, binding := fixtureStateFiles(t)
	now := time.Now()
	proof := json.RawMessage(`{"clean":true,"pristine":true,"never_served":true,"identity_census_complete":true,"started_at":"2026-01-01T00:00:00Z","finished_at":"2026-01-01T00:00:01Z"}`)
	var err error
	binding.LastRestorationID, err = (&RestorationStore{files: files, enrolled: binding}).Save(binding, "pristine", proof)
	if err != nil {
		t.Fatal(err)
	}
	write := func(path string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err = files.Write(path, data); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join("bindings", binding.ProfileID+".json"), binding)
	ack := recoveryAcknowledgement{Version: 1, Nonce: "recover-old", ProfileID: binding.ProfileID, RestorationID: binding.LastRestorationID, Clean: true, Finished: now}
	write("recovery-ack.json", ack)
	stopped := func() (svc.Status, error) { return svc.Status{State: svc.Stopped}, nil }
	if _, err := waitForRecoveryResult(t.Context(), stopped, files, binding.ProfileID, "recover-new"); RecoveryCommandDiagnostic(err) != "Windows recovery service stopped without a current acknowledgement" {
		t.Fatalf("stale acknowledgement result: %v", err)
	}
	queries := 0
	got, err := waitForRecoveryResult(t.Context(), func() (svc.Status, error) {
		queries++
		if queries == 1 {
			return svc.Status{State: svc.StopPending}, nil
		}
		ack.Nonce = "recover-new"
		write("recovery-ack.json", ack)
		return stopped()
	}, files, binding.ProfileID, "recover-new")
	if err != nil || got != binding || queries != 2 {
		t.Fatalf("fresh acknowledgement missed: %v", err)
	}
	delete(files.files, "restoration-"+binding.LastRestorationID+".json")
	if _, err := waitForRecoveryResult(t.Context(), stopped, files, binding.ProfileID, "recover-new"); err == nil {
		t.Fatal("acknowledgement without a strict receipt was accepted")
	}
}

func TestRecoveryResultHonorsDeadlineWhileServiceIsPending(t *testing.T) {
	files, binding := fixtureStateFiles(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := waitForRecoveryResult(ctx, func() (svc.Status, error) {
		return svc.Status{State: svc.StartPending}, nil
	}, files, binding.ProfileID, "recover-new"); !errors.Is(err, context.Canceled) {
		t.Fatalf("pending recovery ignored context: %v", err)
	}
}
