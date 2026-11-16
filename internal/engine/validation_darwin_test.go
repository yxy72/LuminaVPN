package engine

import (
	"errors"
	"testing"
	"time"
)

func TestDarwinValidationCannotBeginOrMutateAfterOriginalDeadline(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	m := Manifest{Created: now.Add(-time.Minute), ValidationTimeout: time.Minute}
	if err := validateDarwinRunStart(m, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := validateDarwinRunStart(m, now); !errors.Is(err, errDarwinValidationExpired) {
		t.Fatalf("expired authorization: %v", err)
	}
	run := t.TempDir()
	if err := guard(run, &State{Manifest: m, Phase: "ready"}); !errors.Is(err, errDarwinValidationExpired) {
		t.Fatalf("expired run still allowed native changes: %v", err)
	}
	m.Created = now.Add(time.Second)
	if err := validateDarwinRunStart(m, now); err == nil {
		t.Fatal("future preparation timestamp extended the time limit")
	}
	m.Created, m.ValidationTimeout = now, 46*time.Minute
	if err := validateDarwinRunStart(m, now); err == nil {
		t.Fatal("validation lasted more than 45 minutes")
	}
	if err := guard(run, &State{Phase: "ready"}); err != nil {
		t.Fatalf("untimed CLI session changed behavior: %v", err)
	}
}
