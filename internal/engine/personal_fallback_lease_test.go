//go:build darwin || windows

package engine

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAutomaticFallbackLeaseUsesObservationRevisionAndBoundsCutoff(t *testing.T) {
	const proofLifetime = 15 * time.Second
	deadline := time.Now().Add(proofLifetime)
	observed := fallbackLeaseState{Revision: "old", NowMS: 7000}
	calls := 0
	readback, err := setFallbackLease(t.Context(), openFallbackLease, deadline, func(ctx context.Context, method string, input, output any) error {
		calls++
		if cutoff, ok := ctx.Deadline(); !ok || !cutoff.Equal(deadline) {
			t.Fatal("control requests must end within the proof lifetime")
		}
		reply := output.(*fallbackLeaseState)
		switch calls {
		case 1:
			if method != "GET" || input != nil {
				t.Fatal("lease must first read the live core clock and revision")
			}
			*reply = observed
		case 2:
			req := input.(fallbackLeaseUpdate)
			if method != "PUT" || req.Revision != observed.Revision || req.Operation != openFallbackLease ||
				req.DeadlineMS <= observed.NowMS || req.DeadlineMS > observed.NowMS+proofLifetime.Milliseconds() {
				t.Fatalf("unexpected lease request %+v", req)
			}
			*reply = fallbackLeaseState{Revision: "new", NowMS: 7100, Active: true, DeadlineMS: req.DeadlineMS}
		default:
			t.Fatal("unexpected repeated lease request")
		}
		return nil
	})
	if err != nil || calls != 2 || !readback.After(time.Now()) || !readback.Before(deadline) {
		t.Fatalf("lease cutoff %v; proof %v; error %v", readback, deadline, err)
	}
}

func TestAutomaticFallbackRenewCannotReopenAnExpiredLease(t *testing.T) {
	readback, err := setFallbackLease(t.Context(), renewFallbackLease, time.Now().Add(time.Second), func(_ context.Context, method string, _, output any) error {
		if method != "GET" {
			t.Fatal("a closed lease must require a separate, fresh open")
		}
		*output.(*fallbackLeaseState) = fallbackLeaseState{Revision: "expired", NowMS: 6000}
		return nil
	})
	if !errors.Is(err, errFallbackLeaseStateChanged) || !readback.IsZero() {
		t.Fatalf("readback %v; error %v", readback, err)
	}
}

func TestAutomaticFallbackLeaseRejectsUnboundReadback(t *testing.T) {
	for _, stale := range []bool{false, true} {
		readback, err := setFallbackLease(t.Context(), renewFallbackLease, time.Now().Add(15*time.Second), func(_ context.Context, method string, input, output any) error {
			reply := output.(*fallbackLeaseState)
			if method == "GET" {
				*reply = fallbackLeaseState{Revision: "old", NowMS: 100, Active: true, DeadlineMS: 500}
				return nil
			}
			update := input.(fallbackLeaseUpdate)
			*reply = fallbackLeaseState{Revision: "new", NowMS: 102, Active: true, DeadlineMS: update.DeadlineMS}
			if stale {
				reply.Revision = update.Revision
			} else {
				reply.DeadlineMS++
			}
			return nil
		})
		if err == nil || !readback.IsZero() {
			t.Fatalf("lease readback must bind the new revision and exact requested cutoff; got %v, %v", readback, err)
		}
	}
}
