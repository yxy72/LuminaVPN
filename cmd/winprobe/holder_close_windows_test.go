//go:build windows

package main

import (
	"errors"
	"fmt"
	"netlaunch/internal/winnet"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestProbeHolderCloseWaitsForExactAbsenceBeforeCleanTerminal(t *testing.T) {
	full := probeIdentityFixture()
	for _, expected := range []winnet.Adapter{full, {GUID: full.GUID, Name: full.Name}} {
		var calls []string
		closed := false
		err := closeProbeAdapterAndConfirm(expected, func() {
			closed = true
			calls = append(calls, "native close")
		}, func(operation, phase string, _ any) error {
			calls = append(calls, operation+":"+phase)
			return nil
		}, func(actual winnet.Adapter, timeout time.Duration, observe func(adapterObservation) error) (adapterObservation, error) {
			if !closed || !reflect.DeepEqual(actual, expected) || timeout != 10*time.Second {
				t.Fatal("absence check preceded close, changed identity or changed bound", actual, timeout)
			}
			calls = append(calls, "wait")
			observation := adapterObservation{State: probeAdapterAbsent, Expected: actual}
			if err := observe(observation); err != nil {
				t.Fatal(err)
			}
			return observation, nil
		}, func() time.Time { return time.Unix(1, 0) })
		result := makeProbeHolderResult(probeHolderIdentityFixture(), err, time.Unix(1, 0))
		if err != nil || !result.Clean || strings.Join(calls, ",") != "CloseAdapter:begin,native close,CloseAdapter:returned,wait,holder_adapter_presence:absent,holder_adapter_absence:absent" {
			t.Fatal("holder did not confirm disappearance before completion", calls, result, err)
		}
	}
}

func TestProbeHolderCloseDiagnosticFailureCannotSkipCleanupOrObservation(t *testing.T) {
	for _, failedOperation := range []string{"CloseAdapter:begin", "CloseAdapter:returned", "holder_adapter_presence:present", "holder_adapter_absence:absent"} {
		t.Run(failedOperation, func(t *testing.T) {
			logErr := errors.New("private log write failed")
			closed, observed := false, false
			err := closeProbeAdapterAndConfirm(probeIdentityFixture(), func() { closed = true }, func(operation, phase string, _ any) error {
				if operation+":"+phase == failedOperation {
					return logErr
				}
				return nil
			}, func(expected winnet.Adapter, _ time.Duration, observe func(adapterObservation) error) (adapterObservation, error) {
				if !closed {
					t.Fatal("close was skipped")
				}
				if err := observe(adapterObservation{State: probeAdapterPresent, Expected: expected}); err != nil {
					t.Fatal("diagnostic failure prevented continued cleanup observation", err)
				}
				observed = true
				return adapterObservation{State: probeAdapterAbsent, Expected: expected}, nil
			}, func() time.Time { return time.Unix(1, 0) })
			if !closed || !observed || !errors.Is(err, logErr) || makeProbeHolderResult(probeHolderIdentityFixture(), err, time.Unix(1, 0)).Clean {
				t.Fatal("diagnostic failure lost, marked clean or prevented cleanup", err)
			}
		})
	}
}

func TestProbeHolderCloseMissingAbsenceCannotProduceCleanTerminal(t *testing.T) {
	expected := probeIdentityFixture()
	for _, state := range []string{probeAdapterPresent, probeAdapterUnknown, probeAdapterConflict} {
		for _, absenceErr := range []error{errors.New("precise absence was not established"), nil} {
			t.Run(fmt.Sprintf("%s/error=%t", state, absenceErr != nil), func(t *testing.T) {
				err := closeProbeAdapterAndConfirm(expected, func() {}, func(string, string, any) error { return nil }, func(winnet.Adapter, time.Duration, func(adapterObservation) error) (adapterObservation, error) {
					return adapterObservation{State: state, Expected: expected}, absenceErr
				}, func() time.Time { return time.Unix(1, 0) })
				result := makeProbeHolderResult(probeHolderIdentityFixture(), err, time.Unix(1, 0))
				if (absenceErr != nil && !errors.Is(err, absenceErr)) || result.Clean || result.Error == "" {
					t.Fatal("close return was confused with removal", result, err)
				}
			})
		}
	}
}

func TestProbeHolderCloseDiagnosticTimeCannotExtendAbsenceBound(t *testing.T) {
	for _, lateOperation := range []string{"CloseAdapter:returned", "holder_adapter_absence:absent"} {
		t.Run(lateOperation, func(t *testing.T) {
			clock := time.Unix(1, 0)
			waited := false
			err := closeProbeAdapterAndConfirm(probeIdentityFixture(), func() {}, func(operation, phase string, _ any) error {
				if operation+":"+phase == lateOperation {
					clock = clock.Add(10 * time.Second)
				}
				return nil
			}, func(expected winnet.Adapter, _ time.Duration, _ func(adapterObservation) error) (adapterObservation, error) {
				waited = true
				return adapterObservation{State: probeAdapterAbsent, Expected: expected}, nil
			}, func() time.Time { return clock })
			if !errors.Is(err, errProbeAdapterAbsenceDeadline) || (lateOperation == "CloseAdapter:returned" && waited) {
				t.Fatal("late diagnostic passed or started an observation after expiry", waited, err)
			}
		})
	}
}
