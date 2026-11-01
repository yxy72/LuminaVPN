package app

import (
	"time"

	"netlaunch/internal/engine"
)

func savedStatus(run string, s engine.Status, now time.Time) map[string]any {
	// Keep the legacy key, but explicitly scope it to the saved snapshot.
	// A v2 coordinator can be healthy without rewriting status.json.
	stale := s.Phase != "stopped" && s.Phase != "prepared" && (s.Updated.IsZero() || now.Sub(s.Updated) > 40*time.Second || now.Before(s.Updated))
	var age *int64
	if !s.Updated.IsZero() && !now.Before(s.Updated) {
		seconds := int64(now.Sub(s.Updated) / time.Second)
		age = &seconds
	}
	return map[string]any{
		"run": run, "status": s, "stale": stale, "snapshot_stale": stale,
		"stale_scope": "saved_snapshot", "snapshot_age_seconds": age,
		"runtime_liveness": "not_checked",
	}
}
