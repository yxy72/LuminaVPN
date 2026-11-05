//go:build windows

package main

import (
	"errors"
	"fmt"
	"netlaunch/internal/platform"
	"time"
)

// A stopped process and an absent adapter do not prove that the holder ran its
// cleanup successfully. This marker is written after all native cleanup and
// event finalization, and checked against the originally published identity.
type probeHolderResult struct {
	Holder   platform.Identity `json:"holder"`
	Finished time.Time         `json:"finished"`
	Clean    bool              `json:"clean"`
	Error    string            `json:"error,omitempty"`
}

func completeProbeHolderIdentity(holder platform.Identity) bool {
	return holder.PID >= 2 && uint64(holder.PID) <= uint64(^uint32(0)) && holder.Birth != "" && holder.Executable != "" && holder.OwnerSID != ""
}

func makeProbeHolderResult(holder platform.Identity, err error, finished time.Time) probeHolderResult {
	if !completeProbeHolderIdentity(holder) {
		err = errors.Join(err, errors.New("incomplete probe adapter holder identity"))
	}
	if finished.IsZero() {
		err = errors.Join(err, errors.New("missing probe adapter holder completion time"))
	}
	result := probeHolderResult{Holder: holder, Finished: finished, Clean: err == nil}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func checkProbeHolderResult(expected platform.Identity, load func() (probeHolderResult, error)) error {
	if !completeProbeHolderIdentity(expected) {
		return errors.New("incomplete published probe adapter holder identity")
	}
	result, err := load()
	if err != nil {
		return fmt.Errorf("read probe adapter holder terminal result: %w", err)
	}
	if result.Holder != expected {
		return errors.New("probe adapter holder terminal identity differs from published holder")
	}
	if result.Finished.IsZero() {
		return errors.New("probe adapter holder terminal result has no completion time")
	}
	if !result.Clean || result.Error != "" {
		return fmt.Errorf("probe adapter holder did not complete cleanly: %s", result.Error)
	}
	return nil
}

// Terminal evidence is a validation gate, never permission to skip cleanup.
// Check it even when cleanup fails so that both failures remain available.
func withProbeHolderResultCheck(cleanup func() error, check func() error) error {
	cleanupErr := cleanup()
	return errors.Join(cleanupErr, check())
}
