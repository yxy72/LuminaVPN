//go:build windows

package main

import (
	"netlaunch/internal/platform"
	"time"
)

// Query failure is unknown, not process exit. In particular it must not stop
// the independent deadline that can still perform ownership-checked recovery.
func monitorProbeOwner(owner platform.Identity, deadline, ticks <-chan time.Time, completed func() bool, query func(int) (platform.Identity, error), recover func(string) error, report func(error)) error {
	for {
		select {
		case <-deadline:
			return recover("deadline")
		case <-ticks:
			if completed() {
				return nil
			}
			actual, err := query(owner.PID)
			if err != nil {
				report(err)
				continue
			}
			if actual != owner {
				return recover("owner_exited")
			}
		}
	}
}
