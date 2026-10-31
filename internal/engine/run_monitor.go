package engine

import (
	"encoding/json"
	"errors"
	"time"

	"netlaunch/internal/platform"
)

type runMonitor struct {
	Version       int               `json:"version"`
	RunSpecDigest string            `json:"run_spec_digest"`
	Runner        platform.Identity `json:"runner"`
	AliveAt       time.Time         `json:"alive_at"`
	ProgressAt    time.Time         `json:"progress_at"`
}

func baselineMonitor(s State) runMonitor {
	return runMonitor{1, s.RunSpecDigest, s.Runner, s.Heartbeat, s.Heartbeat}
}

func decodeMonitor(raw []byte, s State) (runMonitor, error) {
	var m runMonitor
	if json.Unmarshal(raw, &m) != nil || m.Version != 1 || m.RunSpecDigest != s.RunSpecDigest || m.AliveAt.IsZero() || m.ProgressAt.IsZero() || m.ProgressAt.After(m.AliveAt) {
		return m, errors.New("invalid coordinator monitor")
	}
	if m.Runner != s.Runner {
		// Publishing the frozen coordinator replaces the bootstrap identity.
		// An older process cannot renew the new process's watchdog allowance.
		return baselineMonitor(s), nil
	}
	return m, nil
}

func advanceMonitor(s State, m runMonitor, now time.Time, progress bool) (runMonitor, error) {
	if m.Runner != s.Runner || m.RunSpecDigest != s.RunSpecDigest {
		m = baselineMonitor(s)
	}
	if now.Before(m.AliveAt) || now.Before(m.ProgressAt) {
		return m, errors.New("coordinator clock moved backwards")
	}
	m.AliveAt = now
	if progress {
		m.ProgressAt = now
	}
	return m, nil
}

func monitorFailure(s State, m runMonitor, now time.Time) string {
	if m.AliveAt.IsZero() || m.ProgressAt.IsZero() || now.Before(m.AliveAt) || now.Before(m.ProgressAt) {
		return "coordinator_monitor_invalid"
	}
	if now.Sub(m.AliveAt) > 35*time.Second {
		return "coordinator_unresponsive"
	}
	if s.Version >= currentStateVersion {
		limit := 90 * time.Second // initialization includes bounded native setup
		if !s.LastReady.IsZero() || s.Phase == "ready" {
			limit = 35 * time.Second
		}
		if now.Sub(m.ProgressAt) > limit {
			return "coordinator_stalled"
		}
	}
	return ""
}
