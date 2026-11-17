//go:build windows

package winservice

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
	p "netlaunch/internal/serviceprotocol"
)

func readServiceStatus(t *testing.T, ch <-chan svc.Status) svc.Status {
	t.Helper()
	select {
	case status := <-ch:
		return status
	case <-time.After(2 * time.Second):
		t.Fatal("SCM mock status missing")
	}
	return svc.Status{}
}

func TestSCMDispatcherPublishesPendingAndHonorsStopDuringColdValidation(t *testing.T) {
	factoryEntered, release := make(chan struct{}), make(chan struct{})
	requests, statuses, ticks := make(chan svc.ChangeRequest, 4), make(chan svc.Status, 16), make(chan time.Time, 4)
	done := make(chan uint32, 1)
	var serving, restoring atomic.Int32
	handler := serviceHandler{factory: func() (*Host, error) { close(factoryEntered); <-release; return &Host{}, nil }, validate: func(*Host) error { return nil }, serve: func(ctx context.Context, _ *Host) error { serving.Add(1); <-ctx.Done(); return nil }, restore: func(context.Context, *Host) error { restoring.Add(1); return nil }, ticks: ticks, initExpired: make(chan time.Time)}
	go func() { _, code := handler.Execute(nil, requests, statuses); done <- code }()
	first := readServiceStatus(t, statuses)
	if first.State != svc.StartPending || first.CheckPoint == 0 {
		t.Fatal("slow initialization preceded SCM dispatcher")
	}
	<-factoryEntered
	ticks <- time.Now()
	next := readServiceStatus(t, statuses)
	if next.State != svc.StartPending || next.CheckPoint <= first.CheckPoint {
		t.Fatal("cold validation did not publish progress")
	}
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	if readServiceStatus(t, statuses).State != svc.StopPending {
		t.Fatal("stop ignored during factory")
	}
	close(release)
	if readServiceStatus(t, statuses).State != svc.StopPending {
		t.Fatal("stop transitioned to running")
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatal("mock restore failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("initialization stop blocked")
	}
	if serving.Load() != 0 || restoring.Load() != 1 {
		t.Fatal("stop during initialization served requests or skipped owned restoration")
	}
}

func TestSCMFailedOrExpiredFactoryNeverReportsRunning(t *testing.T) {
	for _, expire := range []bool{false, true} {
		t.Run(map[bool]string{false: "failure", true: "expiry"}[expire], func(t *testing.T) {
			requests, statuses := make(chan svc.ChangeRequest), make(chan svc.Status, 8)
			expired := make(chan time.Time, 1)
			release := make(chan struct{})
			done := make(chan uint32, 1)
			handler := serviceHandler{factory: func() (*Host, error) {
				if expire {
					<-release
				}
				return nil, errors.New("unavailable")
			}, ticks: make(chan time.Time), initExpired: expired, validate: func(*Host) error { t.Error("failed factory was validated"); return nil }}
			go func() { _, code := handler.Execute(nil, requests, statuses); done <- code }()
			if readServiceStatus(t, statuses).State != svc.StartPending {
				t.Fatal("initial state is not pending")
			}
			if expire {
				expired <- time.Now()
			}
			select {
			case code := <-done:
				if code != 1 {
					t.Fatal("failed factory reported success")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("factory expiry ignored")
			}
			close(release)
			select {
			case status := <-statuses:
				if status.State == svc.Running {
					t.Fatal("unready host reported running")
				}
			default:
			}
		})
	}
}

func TestRecoveryServiceReportsOnlyBoundedSCMFailureStages(t *testing.T) {
	internalErr := errors.New("private path or other internal information")
	proofErr := fmt.Errorf("private error context: %w", &p.Error{Code: "RESTORE_PROOF_INCOMPLETE", Message: "private error content"})
	cases := []struct {
		name                string
		factory, validation error
		restoration         error
		want                uint32
	}{
		{name: "factory failure", factory: internalErr, want: recoveryExitFactory},
		{name: "validation failure", validation: internalErr, want: recoveryExitValidation},
		{name: "unclassified restoration failure", restoration: internalErr, want: recoveryExitRestore},
		{name: "unknown typed restoration failure", restoration: &p.Error{Code: "PRIVATE_CODE"}, want: recoveryExitRestore},
		{name: "strict proof failure", restoration: proofErr, want: recoveryExitProof},
		{name: "restoration timeout", restoration: context.DeadlineExceeded, want: recoveryExitRestoreTimed},
		{name: "missing acknowledgement", want: recoveryExitAcknowledgement},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, recovery := range []bool{false, true} {
				statuses := make(chan svc.Status, 8)
				requests := make(chan svc.ChangeRequest, 1)
				if !recovery {
					requests <- svc.ChangeRequest{Cmd: svc.Stop}
				}
				h := serviceHandler{
					factory:      func() (*Host, error) { return &Host{}, tc.factory },
					validate:     func(*Host) error { return tc.validation },
					restore:      func(context.Context, *Host) error { return tc.restoration },
					recoveryOnly: recovery,
				}
				specific, code := h.Execute(nil, requests, statuses)
				if recovery {
					if !specific || code != tc.want || recoveryServiceExitStage(code) == "unknown" {
						t.Fatalf("recovery returned (%v, %d), want a known SCM exit code %d", specific, code, tc.want)
					}
				} else {
					want := uint32(1)
					if tc.want == recoveryExitAcknowledgement {
						want = 0 // The main service does not write a recovery acknowledgement.
					}
					if specific || code != want {
						t.Fatalf("main service returned (%v, %d), want (false, %d)", specific, code, want)
					}
				}
			}
		})
	}
}
