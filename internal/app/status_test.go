package app

import (
	"netlaunch/internal/engine"
	"testing"
	"time"
)

func TestSavedStatusDoesNotClaimCoordinatorLiveness(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		phase string
		stamp time.Time
		stale bool
	}{
		{"ready", now.Add(-time.Hour), true}, {"ready", now, false},
		{"ready", time.Time{}, true}, {"ready", now.Add(time.Hour), true},
		{"stopped", now.Add(-time.Hour), false}, {"prepared", now.Add(-time.Hour), false},
	} {
		r := savedStatus("run", engine.Status{Phase: tc.phase, Updated: tc.stamp}, now)
		if r["stale"] != tc.stale || r["snapshot_stale"] != tc.stale || r["stale_scope"] != "saved_snapshot" || r["runtime_liveness"] != "not_checked" {
			t.Fatal(r)
		}
	}
}
