package winservice

import (
	"errors"
	"testing"
	"time"
)

func TestOwnedJobExitRequiresObservedZeroBeforeDeadline(t *testing.T) {
	start := time.Now()
	now := start
	if waitJobEmpty(start.Add(time.Second), func() time.Time { return now }, func(d time.Duration) { now = now.Add(d) }, func() (uint32, error) { now = now.Add(2 * time.Second); return 0, nil }) == nil {
		t.Fatal("late zero was accepted")
	}
	now = start
	if waitJobEmpty(start.Add(time.Second), func() time.Time { return now }, func(d time.Duration) { now = now.Add(d) }, func() (uint32, error) { return 0, errors.New("query denied") }) == nil {
		t.Fatal("API failure became owned worker absence")
	}
	now = start
	if err := waitJobEmpty(start.Add(time.Second), func() time.Time { return now }, func(d time.Duration) { now = now.Add(d) }, func() (uint32, error) {
		if now.Sub(start) < 100*time.Millisecond {
			return 1, nil
		}
		return 0, nil
	}); err != nil {
		t.Fatal(err)
	}
}
