package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestSamplingBudgetKeepsOnlyCompletedObservations(t *testing.T) {
	var active atomic.Int32
	values := sampleNodes(context.Background(), []string{"good", "failed", "slow"}, 100*time.Millisecond, 3, func(ctx context.Context, n string) (int, bool) {
		active.Add(1)
		defer active.Add(-1)
		switch n {
		case "good":
			return 10, true
		case "failed":
			return -1, true
		}
		<-ctx.Done()
		return -1, true // Even a late failure must not be published.
	})
	if len(values) != 2 || values["good"] != 10 || values["failed"] != -1 {
		t.Fatal(values)
	}
	until := time.Now().Add(time.Second)
	for active.Load() != 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 0 {
		t.Fatal("workers outlived cancellation")
	}
}

func TestSamplingCancellationDoesNotStartQueuedNodes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	values := sampleNodes(ctx, []string{"first", "queued", "queued2"}, time.Hour, 1, func(ctx context.Context, n string) (int, bool) { calls.Add(1); cancel(); <-ctx.Done(); return 0, false })
	if len(values) != 0 {
		t.Fatal(values)
	}
	time.Sleep(20 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatal("started work after cancellation", calls.Load())
	}
}
