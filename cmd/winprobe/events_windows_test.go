//go:build windows

package main

import (
	"errors"
	"testing"
	"time"
)

func TestNativeErrorIsRetainedWithoutDisablingLifecycleRecording(t *testing.T) {
	nativeErr := errors.New("Wintun adapter removal error")
	storageErr := errors.New("fixture has no event store")
	log := &probeEvents{}
	log.recordNativeError(nativeErr)
	if log.err != nil {
		t.Fatal("native failure disabled later lifecycle evidence")
	}
	log.err = storageErr
	err := log.finish("holder", nil)
	if !errors.Is(err, nativeErr) || !errors.Is(err, storageErr) {
		t.Fatal(err)
	}
}

func TestDiagnosticInitializationFailureDoesNotSkipCleanup(t *testing.T) {
	diagnosticErr := errors.New("diagnostic initialization failed")
	cleaned := false
	err := withProbeCleanupDiagnostics(func() (*probeEvents, error) { return nil, diagnosticErr }, func(log *probeEvents) error {
		cleaned = true
		return log.finish("recovery", nil)
	})
	if !cleaned || !errors.Is(err, diagnosticErr) {
		t.Fatal("cleanup skipped or diagnostic failure hidden", cleaned, err)
	}
	result := mergeRecoveryResult(nil, "deadline", err, time.Time{})
	if result["recovered"] != false {
		t.Fatal("diagnostic failure incorrectly passed validation", result)
	}
}

func TestDiagnosticRecordFailureStillRunsCleanup(t *testing.T) {
	diagnosticErr := errors.New("private event write failed")
	cleaned := false
	err := withProbeCleanupDiagnostics(func() (*probeEvents, error) { return &probeEvents{err: diagnosticErr}, nil }, func(log *probeEvents) error {
		// Reporting failure does not become a guard on the actual release.
		recordErr := log.add("holder", "timeout", nil)
		cleaned = true
		return recordErr
	})
	if !cleaned || !errors.Is(err, diagnosticErr) {
		t.Fatal(cleaned, err)
	}
}
