//go:build windows

package main

import (
	"errors"
	"fmt"
	"netlaunch/internal/platform"
	"time"
)

var errProbeHolderCloseTimeout = errors.New("adapter holder did not close within bound; exact identity termination required")

// waitProbeHolderExit waits for the published holder, then bounds termination
// of that exact identity. A forced exit is never a clean recovery result.
func waitProbeHolderExit(expected platform.Identity, query func(int) (platform.Identity, error), stop func(platform.Identity) error, now func() time.Time, sleep func(time.Duration), report func() error) (stopped bool, err error) {
	wait := func(deadline time.Time, interval time.Duration) (bool, error) {
		for {
			actual, err := query(expected.PID)
			if err != nil {
				return false, fmt.Errorf("query probe adapter holder identity: %w", err)
			}
			// The identity query can itself block. Only a result received before
			// the absolute deadline can confirm an exit within this window.
			remaining := deadline.Sub(now())
			if remaining <= 0 {
				return false, nil
			}
			if actual != expected {
				return true, nil
			}
			if remaining < interval {
				interval = remaining
			}
			sleep(interval)
		}
	}
	stopped, err = wait(now().Add(15*time.Second), 100*time.Millisecond)
	if err != nil || stopped {
		return stopped, err
	}
	forced := errProbeHolderCloseTimeout
	if report != nil {
		forced = errors.Join(forced, report())
	}
	// Reporting a timeout must not leave the owned process running. StopIdentity
	// receives only the frozen published identity, never a newly queried one.
	if err := stop(expected); err != nil {
		return false, errors.Join(forced, fmt.Errorf("terminate probe adapter holder: %w", err))
	}
	stopped, err = wait(now().Add(5*time.Second), 50*time.Millisecond)
	if err != nil {
		return false, errors.Join(forced, err)
	}
	if !stopped {
		return false, errors.Join(forced, errors.New("holder exit was not confirmed within termination bound"))
	}
	return true, forced
}
