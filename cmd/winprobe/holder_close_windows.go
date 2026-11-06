//go:build windows

package main

import (
	"errors"
	"fmt"
	"netlaunch/internal/winnet"
	"time"
)

// CloseAdapter returning is not evidence that Windows removed the interface.
// Keep the dedicated holder (and its Wintun DLL/logger) alive while checking
// the exact identity, before it can publish a clean terminal result. This uses
// the existing 10-second absence bound, within the watcher's 15-second wait.
func closeProbeAdapterAndConfirm(expected winnet.Adapter, close func(), record func(string, string, any) error, wait func(winnet.Adapter, time.Duration, func(adapterObservation) error) (adapterObservation, error), now func() time.Time) error {
	beginErr := record("CloseAdapter", "begin", nil)
	close()
	deadline := now().Add(10 * time.Second)
	returnedErr := record("CloseAdapter", "returned", map[string]any{"returns_void": true})
	var observationErr error
	observation := adapterObservation{State: probeAdapterUnknown, Expected: expected}
	waitErr := errProbeAdapterAbsenceDeadline
	if remaining := deadline.Sub(now()); remaining > 0 {
		observation, waitErr = wait(expected, remaining, func(o adapterObservation) error {
			observationErr = errors.Join(observationErr, record("holder_adapter_presence", o.State, o))
			// Diagnostic storage cannot prevent the remaining native observations.
			return nil
		})
	}
	if waitErr == nil && observation.State != probeAdapterAbsent {
		waitErr = fmt.Errorf("holder did not confirm probe adapter disappearance: %s", observation.State)
	}
	finalErr := record("holder_adapter_absence", observation.State, observation)
	// Returned/final diagnostic I/O belongs to the same fixed observation
	// window. Timely native absence followed by late evidence cannot pass.
	if !now().Before(deadline) {
		waitErr = errors.Join(waitErr, errProbeAdapterAbsenceDeadline)
	}
	return errors.Join(beginErr, returnedErr, observationErr, waitErr, finalErr)
}
