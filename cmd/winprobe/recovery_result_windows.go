//go:build windows

package main

import (
	"errors"
	"os"
	"time"
)

// The previous outcome is evidence, not authority to clean up. A damaged
// history file is preserved while owned cleanup still runs and fails validation.
func withProbeRecoveryHistory(load func() (map[string]any, error), cleanup func(map[string]any, error) error) error {
	previous, err := load()
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return errors.Join(err, cleanup(previous, err))
}

// mergeRecoveryResult records the latest outcome without discarding the first
// failure. Attempt IDs and start times belong to the separate per-attempt log.
// A repeated successful verification leaves the original success unchanged.
func mergeRecoveryResult(previous map[string]any, reason string, err error, finished time.Time) map[string]any {
	if previous["recovered"] == true && err == nil {
		return previous
	}
	result := make(map[string]any, len(previous)+5)
	for key, value := range previous {
		result[key] = value
	}
	result["recovered"] = err == nil
	result["reason"] = reason
	result["finished"] = finished
	result["latest_error"] = ""
	if err != nil {
		result["latest_error"] = err.Error()
		if result["first_failure"] == nil {
			result["first_failure"] = map[string]any{
				"time":   finished,
				"reason": reason,
				"error":  err.Error(),
			}
		}
	}
	return result
}
