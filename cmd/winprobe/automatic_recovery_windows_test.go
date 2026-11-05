//go:build windows

package main

import (
	"errors"
	"testing"
	"time"
)

func TestAutomaticRetryCannotEraseForcedHolderTimeout(t *testing.T) {
	attempts, reports := 0, 0
	resources, err := runAutomaticRecoveryAttempts(func() error {
		attempts++
		if attempts == 1 {
			return errProbeHolderCloseTimeout
		}
		return nil // the exact holder and adapter are now absent
	}, func(attempt int, err error) error { reports++; return nil }, func() {})
	if !resources || !errors.Is(err, errProbeHolderCloseTimeout) || attempts != 2 || reports != 1 {
		t.Fatal(resources, err, attempts, reports)
	}
	terminal := mergeRecoveryResult(nil, "deadline", err, time.Time{})
	terminal["resources_recovered"] = resources
	if terminal["recovered"] != false || terminal["resources_recovered"] != true || terminal["first_failure"] == nil {
		t.Fatal(terminal)
	}
}

func TestAutomaticRetryContinuesAfterDiagnosticWriteFailure(t *testing.T) {
	diagnosticErr, firstErr := errors.New("failure report write denied"), errors.New("first cleanup incomplete")
	attempts := 0
	resources, err := runAutomaticRecoveryAttempts(func() error {
		attempts++
		if attempts == 1 {
			return firstErr
		}
		return nil
	}, func(int, error) error { return diagnosticErr }, func() {})
	if attempts != 2 || !resources || !errors.Is(err, firstErr) || !errors.Is(err, diagnosticErr) {
		t.Fatal(attempts, resources, err)
	}
}

func TestAutomaticFirstAttemptPassesWithoutInventedFailure(t *testing.T) {
	resources, err := runAutomaticRecoveryAttempts(func() error { return nil }, func(int, error) error { t.Fatal("no failure to record"); return nil }, func() { t.Fatal("no retry needed") })
	if !resources || err != nil {
		t.Fatal(resources, err)
	}
}

func TestAutomaticPersistentFailureRemainsUnrecovered(t *testing.T) {
	failure := errors.New("owned adapter still present")
	attempts := 0
	resources, err := runAutomaticRecoveryAttempts(func() error { attempts++; return failure }, func(int, error) error { return nil }, func() {})
	if resources || attempts != 2 || !errors.Is(err, failure) {
		t.Fatal(resources, attempts, err)
	}
}
