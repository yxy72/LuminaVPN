//go:build windows

package winservice

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
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
