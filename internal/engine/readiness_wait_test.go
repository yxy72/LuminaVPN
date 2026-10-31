package engine

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestReadinessDeadlineCancelsInFlightCheck(t *testing.T) {
	called := false
	err := waitReady(context.Background(), 30*time.Millisecond, func() error { return nil }, func(ctx context.Context) error {
		called = true
		<-ctx.Done()
		return nil // A backend's late success cannot mark the stage ready.
	})
	if !called || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(called, err)
	}
}

func TestReadinessParentCancellationAndTerminalFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := waitReady(ctx, time.Hour, func() error { t.Fatal("pulse after cancel"); return nil }, func(context.Context) error { t.Fatal("check after cancel"); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	wanted := errors.New("authentication required")
	calls := 0
	err = waitReady(context.Background(), time.Hour, func() error { return nil }, func(context.Context) error {
		calls++
		return &terminalReadinessError{wanted}
	})
	if calls != 1 || !errors.Is(err, wanted) {
		t.Fatal(calls, err)
	}
}

func TestReadinessCancellationDuringRetryRetainsCause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wanted := errors.New("core unavailable")
	err := waitReady(ctx, time.Hour, func() error { return nil }, func(context.Context) error { cancel(); return wanted })
	if !errors.Is(err, context.Canceled) || !errors.Is(err, wanted) {
		t.Fatal(err)
	}
}
