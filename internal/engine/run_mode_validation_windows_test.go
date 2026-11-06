//go:build windows && windows_client && windows_client_validation

package engine

import (
	"strings"
	"testing"
	"time"
)

func TestValidationNativeMutationGuardRejectsLegacyWithoutIO(t *testing.T) {
	for _, manifest := range []Manifest{{}, {ValidationTimeout: 12 * time.Hour}, {Mode: Legacy}, {Mode: Daily}} {
		state := State{Manifest: manifest}
		if err := guard("unused-fixture-path", &state); err == nil || !strings.Contains(err.Error(), "explicit validation mode required") {
			t.Fatal("legacy mode reached native mutation guard", manifest)
		}
	}
}
