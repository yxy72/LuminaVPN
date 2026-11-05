//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestUnreadableHistoryDoesNotBlockCleanupOrGetOverwritten(t *testing.T) {
	historyErr := errors.New("old result is malformed")
	cleaned, preserved := false, false
	err := withProbeRecoveryHistory(func() (map[string]any, error) { return nil, historyErr }, func(previous map[string]any, readErr error) error {
		cleaned = true
		preserved = readErr != nil
		result := mergeRecoveryResult(previous, "manual", readErr, time.Time{})
		if result["recovered"] != false {
			t.Fatal("unreadable history incorrectly passed", result)
		}
		return readErr
	})
	if !cleaned || !preserved || !errors.Is(err, historyErr) {
		t.Fatal(cleaned, preserved, err)
	}
}

func TestRecoveryResultFailureThenManualSuccessRetainsHistory(t *testing.T) {
	failedAt := time.Date(2026, time.November, 5, 9, 40, 16, 0, time.UTC)
	succeededAt := failedAt.Add(13 * time.Minute)
	failure := errors.New("release probe adapter: probe adapter remains after close")
	failed := mergeRecoveryResult(nil, "deadline", failure, failedAt)
	if failed["recovered"] != false || failed["latest_error"] != failure.Error() || failed["reason"] != "deadline" {
		t.Fatalf("failure reported as recovered or lost: %#v", failed)
	}
	firstFailure := map[string]any{"time": failedAt, "reason": "deadline", "error": failure.Error()}
	if !reflect.DeepEqual(failed["first_failure"], firstFailure) {
		t.Fatalf("missing first failure: %#v", failed["first_failure"])
	}

	succeeded := mergeRecoveryResult(failed, "manual", nil, succeededAt)
	if succeeded["recovered"] != true || succeeded["latest_error"] != "" || succeeded["reason"] != "manual" || succeeded["finished"] != succeededAt {
		t.Fatalf("manual recovery did not become the current outcome: %#v", succeeded)
	}
	if !reflect.DeepEqual(succeeded["first_failure"], firstFailure) {
		t.Fatalf("manual recovery erased the automatic failure: %#v", succeeded)
	}
	if failed["recovered"] != false || failed["finished"] != failedAt || failed["latest_error"] != failure.Error() {
		t.Fatalf("merge mutated its previous result: %#v", failed)
	}

	repeated := mergeRecoveryResult(succeeded, "manual", nil, succeededAt.Add(time.Minute))
	if !reflect.DeepEqual(repeated, succeeded) || repeated["finished"] != succeededAt {
		t.Fatalf("repeat recovery replaced the original success: %#v", repeated)
	}
}

func TestRecoveryResultFailureAfterSuccessClearsRecovered(t *testing.T) {
	firstAt := time.Date(2026, time.November, 5, 9, 40, 0, 0, time.UTC)
	previous := map[string]any{
		"recovered": true,
		"reason":    "owner_exited",
		"finished":  firstAt,
		"metadata":  "retain unknown fields",
	}
	failure := errors.New("journal readback failed")
	failedAt := firstAt.Add(time.Minute)
	result := mergeRecoveryResult(previous, "manual", failure, failedAt)
	if result["recovered"] != false || result["latest_error"] != failure.Error() || result["finished"] != failedAt || result["reason"] != "manual" {
		t.Fatalf("later failed verification still reports the earlier success: %#v", result)
	}
	if result["metadata"] != previous["metadata"] || previous["recovered"] != true || previous["finished"] != firstAt {
		t.Fatalf("merge lost metadata or mutated the original success: previous=%#v result=%#v", previous, result)
	}
	firstFailure := result["first_failure"]
	second := mergeRecoveryResult(result, "manual", errors.New("different readback failure"), failedAt.Add(time.Second))
	if second["latest_error"] != "different readback failure" || !reflect.DeepEqual(second["first_failure"], firstFailure) {
		t.Fatalf("later failure replaced the first failure or omitted current error: %#v", second)
	}
}

func TestRecoveryResultRetainsHistoryAfterJSONReadback(t *testing.T) {
	firstAt := time.Date(2026, time.November, 5, 9, 40, 0, 123, time.UTC)
	initial := mergeRecoveryResult(nil, "deadline", errors.New("first failure"), firstAt)
	encoded, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	var previous map[string]any
	if err := json.Unmarshal(encoded, &previous); err != nil {
		t.Fatal(err)
	}
	firstFailure := previous["first_failure"]
	result := mergeRecoveryResult(previous, "manual", nil, firstAt.Add(time.Minute))
	if result["recovered"] != true || !reflect.DeepEqual(result["first_failure"], firstFailure) {
		t.Fatalf("persisted first failure was lost: %#v", result)
	}
	unchanged, err := json.Marshal(previous)
	if err != nil || string(unchanged) != string(encoded) {
		t.Fatalf("previous persisted result changed: %s (%v)", unchanged, err)
	}
}

func TestRecoveryResultInitialSuccessDoesNotInventFailure(t *testing.T) {
	finished := time.Date(2026, time.November, 5, 9, 40, 0, 0, time.UTC)
	result := mergeRecoveryResult(nil, "owner_exited", nil, finished)
	if result["recovered"] != true || result["latest_error"] != "" || result["reason"] != "owner_exited" || result["finished"] != finished {
		t.Fatalf("incorrect initial success: %#v", result)
	}
	if _, exists := result["first_failure"]; exists {
		t.Fatalf("initial success invented a failure: %#v", result)
	}
}
