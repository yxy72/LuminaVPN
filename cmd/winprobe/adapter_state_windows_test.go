//go:build windows

package main

import (
	"errors"
	"netlaunch/internal/winnet"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func probeIdentityFixture() winnet.Adapter {
	return winnet.Adapter{Index: 43, LUID: 14918723538255872, GUID: "{C3EC67D1-F014-419F-A00F-01ED56071924}", Name: "NL-Probe-owned-fixture", Type: 53, Up: true}
}

func TestProbeAdapterObservationRequiresExactAbsence(t *testing.T) {
	expected := probeIdentityFixture()
	down := expected
	down.Up = false
	reusedIndex := expected
	reusedIndex.LUID++
	reusedIndex.GUID = "{B3EC67D1-F014-419F-A00F-01ED56071924}"
	reusedIndex.Name = "foreign-index"
	reusedName := reusedIndex
	reusedName.Index++
	reusedName.Name = expected.Name
	tests := []struct {
		name              string
		rows              []winnet.Adapter
		enumerationErr    error
		byLUID, byIndex   *winnet.Adapter
		luidErr, indexErr error
		state             string
		wantErr           bool
	}{
		{name: "all absent", state: probeAdapterAbsent},
		{name: "exact remains", rows: []winnet.Adapter{expected}, byLUID: &expected, byIndex: &expected, state: probeAdapterPresent},
		{name: "down remains", rows: []winnet.Adapter{down}, byLUID: &down, byIndex: &down, state: probeAdapterPresent},
		{name: "deleting between queries", rows: []winnet.Adapter{expected}, state: probeAdapterPresent},
		{name: "late native row", byLUID: &expected, state: probeAdapterPresent},
		{name: "enumeration API failure", enumerationErr: windows.ERROR_ACCESS_DENIED, state: probeAdapterUnknown, wantErr: true},
		{name: "LUID API failure", luidErr: windows.ERROR_ACCESS_DENIED, state: probeAdapterUnknown, wantErr: true},
		{name: "index API failure", indexErr: windows.ERROR_INVALID_DATA, state: probeAdapterUnknown, wantErr: true},
		{name: "same name new generation", rows: []winnet.Adapter{reusedName}, state: probeAdapterConflict, wantErr: true},
		{name: "index reused", byIndex: &reusedIndex, state: probeAdapterConflict, wantErr: true},
		{name: "name conflict beside owned", rows: []winnet.Adapter{expected, reusedName}, byLUID: &expected, byIndex: &expected, state: probeAdapterConflict, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queries := 0
			actual, e := queryProbeAdapterWith(expected, func() ([]winnet.Adapter, error) { return tt.rows, tt.enumerationErr }, func(luid uint64, index uint32) (winnet.Adapter, error) {
				queries++
				if luid == expected.LUID && index == 0 {
					if tt.byLUID != nil {
						return *tt.byLUID, tt.luidErr
					}
					if tt.luidErr != nil {
						return winnet.Adapter{}, tt.luidErr
					}
					return winnet.Adapter{}, windows.ERROR_FILE_NOT_FOUND
				}
				if luid == 0 && index == expected.Index {
					if tt.byIndex != nil {
						return *tt.byIndex, tt.indexErr
					}
					if tt.indexErr != nil {
						return winnet.Adapter{}, tt.indexErr
					}
					return winnet.Adapter{}, windows.ERROR_NOT_FOUND
				}
				t.Fatal("lookup must independently query exactly one owned key")
				return winnet.Adapter{}, errors.New("unexpected key")
			})
			if actual.State != tt.state || (e != nil) != tt.wantErr || queries != 2 {
				t.Fatalf("state=%s error=%v queries=%d", actual.State, e, queries)
			}
		})
	}
}

func TestProbeAdapterMissingIdentityNeverQueriesOrProvesAbsence(t *testing.T) {
	partial := probeIdentityFixture()
	partial.Index = 0
	for _, expected := range []winnet.Adapter{{}, partial} {
		_, e := queryProbeAdapterWith(expected, func() ([]winnet.Adapter, error) {
			t.Fatal("incomplete identity must not query")
			return nil, nil
		}, func(uint64, uint32) (winnet.Adapter, error) {
			t.Fatal("incomplete identity must not query")
			return winnet.Adapter{}, nil
		})
		if e == nil {
			t.Fatal("missing publication was considered absent")
		}
	}
}

func TestProbeAdapterRequestedGUIDIntent(t *testing.T) {
	owned := probeIdentityFixture()
	intent := winnet.Adapter{GUID: owned.GUID, Name: owned.Name}
	reusedName := owned
	reusedName.GUID = "{B3EC67D1-F014-419F-A00F-01ED56071924}"
	reusedIndex := owned
	reusedIndex.Index++
	tests := []struct {
		name           string
		rows           []winnet.Adapter
		enumerationErr error
		luid           uint64
		conversionErr  error
		row            *winnet.Adapter
		lookupErr      error
		state          string
		wantErr        bool
	}{
		{name: "absent after interrupted creation", conversionErr: windows.ERROR_NOT_FOUND, state: probeAdapterAbsent},
		{name: "native absent alias present", rows: []winnet.Adapter{owned}, conversionErr: windows.ERROR_NOT_FOUND, state: probeAdapterPresent},
		{name: "mapped GUID row deleting", luid: owned.LUID, lookupErr: windows.ERROR_FILE_NOT_FOUND, state: probeAdapterPresent},
		{name: "exact new adapter", rows: []winnet.Adapter{owned}, luid: owned.LUID, row: &owned, state: probeAdapterPresent},
		{name: "unknown conversion", conversionErr: windows.ERROR_ACCESS_DENIED, state: probeAdapterUnknown, wantErr: true},
		{name: "unknown enumeration", enumerationErr: windows.ERROR_ACCESS_DENIED, conversionErr: windows.ERROR_NOT_FOUND, state: probeAdapterUnknown, wantErr: true},
		{name: "unknown native row", luid: owned.LUID, lookupErr: windows.ERROR_ACCESS_DENIED, state: probeAdapterUnknown, wantErr: true},
		{name: "empty successful conversion", state: probeAdapterUnknown, wantErr: true},
		{name: "same name another GUID", rows: []winnet.Adapter{reusedName}, conversionErr: windows.ERROR_NOT_FOUND, state: probeAdapterConflict, wantErr: true},
		{name: "GUID lookup wrong identity", luid: owned.LUID, row: &reusedName, state: probeAdapterConflict, wantErr: true},
		{name: "GUID sources disagree", rows: []winnet.Adapter{owned}, luid: owned.LUID, row: &reusedIndex, state: probeAdapterConflict, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, e := queryProbeAdapterIntentWith(intent, func() ([]winnet.Adapter, error) { return tt.rows, tt.enumerationErr }, func(guid string) (uint64, error) {
				if guid != intent.GUID {
					t.Fatal("conversion escaped requested GUID")
				}
				return tt.luid, tt.conversionErr
			}, func(luid uint64, index uint32) (winnet.Adapter, error) {
				if luid != tt.luid || index != 0 {
					t.Fatal("intent lookup escaped converted LUID")
				}
				if tt.row != nil {
					return *tt.row, tt.lookupErr
				}
				return winnet.Adapter{}, tt.lookupErr
			})
			if actual.State != tt.state || (e != nil) != tt.wantErr {
				t.Fatalf("state=%s error=%v", actual.State, e)
			}
		})
	}
}

func TestProbeAdapterWaitDelayedDisappearanceAndBound(t *testing.T) {
	for _, disappear := range []bool{true, false} {
		name := "always present"
		if disappear {
			name = "delayed disappearance"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Unix(1, 0)
			start := now
			calls := 0
			var observed []string
			last, e := waitProbeAdapterAbsentWith(probeIdentityFixture(), 10*time.Second, func(o adapterObservation) error {
				observed = append(observed, o.State)
				return nil
			}, func(expected winnet.Adapter) (adapterObservation, error) {
				calls++
				state := probeAdapterPresent
				if disappear && calls == 3 {
					state = probeAdapterAbsent
				}
				return adapterObservation{State: state, Expected: expected}, nil
			}, func() time.Time { return now }, func(d time.Duration) { now = now.Add(d) })
			if disappear {
				if e != nil || last.State != probeAdapterAbsent || now.Sub(start) != 200*time.Millisecond || strings.Join(observed, ",") != "present,absent" {
					t.Fatalf("last=%s error=%v elapsed=%v observed=%v", last.State, e, now.Sub(start), observed)
				}
			} else if e == nil || last.State != probeAdapterPresent || now.Sub(start) != 10*time.Second || calls != 101 || len(observed) != 1 {
				t.Fatalf("unbounded or incorrect wait: last=%s error=%v elapsed=%v calls=%d observed=%v", last.State, e, now.Sub(start), calls, observed)
			}
		})
	}
}

func TestProbeAdapterWaitStopsOnQueryConflictOrRecordingError(t *testing.T) {
	for _, state := range []string{probeAdapterUnknown, probeAdapterConflict, probeAdapterAbsent} {
		t.Run(state, func(t *testing.T) {
			errFixture := errors.New("fixture error")
			calls := 0
			_, e := waitProbeAdapterAbsentWith(probeIdentityFixture(), time.Second, func(adapterObservation) error {
				if state == probeAdapterAbsent {
					return errFixture
				}
				return nil
			}, func(winnet.Adapter) (adapterObservation, error) {
				calls++
				if state == probeAdapterAbsent {
					return adapterObservation{State: state}, nil
				}
				return adapterObservation{State: state}, errFixture
			}, func() time.Time { return time.Unix(1, 0) }, func(time.Duration) { t.Fatal("failed/unknown query must not wait or pass") })
			if !errors.Is(e, errFixture) || calls != 1 {
				t.Fatalf("error=%v calls=%d", e, calls)
			}
		})
	}
}

func TestProbeAdapterWaitIncludesQueryAndObserverInDeadline(t *testing.T) {
	for _, tt := range []struct {
		name                        string
		queryDuration, observerTime time.Duration
		wantDeadline                bool
	}{
		{name: "initial query returns just before deadline", queryDuration: 10*time.Second - time.Nanosecond},
		{name: "initial query returns at deadline", queryDuration: 10 * time.Second, wantDeadline: true},
		{name: "initial query returns after deadline", queryDuration: 11 * time.Second, wantDeadline: true},
		{name: "observer returns at deadline", queryDuration: 9 * time.Second, observerTime: time.Second, wantDeadline: true},
		{name: "observer returns after deadline", queryDuration: 9 * time.Second, observerTime: 2 * time.Second, wantDeadline: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			current := time.Unix(1, 0)
			queries, observations := 0, 0
			last, err := waitProbeAdapterAbsentWith(probeIdentityFixture(), 10*time.Second, func(o adapterObservation) error {
				observations++
				if o.State != probeAdapterAbsent {
					t.Fatal("lost final observation", o.State)
				}
				current = current.Add(tt.observerTime)
				return nil
			}, func(expected winnet.Adapter) (adapterObservation, error) {
				queries++
				current = current.Add(tt.queryDuration)
				return adapterObservation{State: probeAdapterAbsent, Expected: expected}, nil
			}, func() time.Time { return current }, func(time.Duration) { t.Fatal("completed query must not start another wait") })
			if errors.Is(err, errProbeAdapterAbsenceDeadline) != tt.wantDeadline || (err != nil) != tt.wantDeadline || last.State != probeAdapterAbsent || queries != 1 || observations != 1 {
				t.Fatalf("state=%s error=%v queries=%d observations=%d", last.State, err, queries, observations)
			}
		})
	}
}

func TestProbeAdapterWaitPreservesErrorsWhenDeadlineExceeded(t *testing.T) {
	current := time.Unix(1, 0)
	queryErr, recordErr := errors.New("native query failed"), errors.New("observation write failed")
	_, err := waitProbeAdapterAbsentWith(probeIdentityFixture(), time.Second, func(adapterObservation) error {
		current = current.Add(time.Second)
		return recordErr
	}, func(winnet.Adapter) (adapterObservation, error) {
		return adapterObservation{State: probeAdapterUnknown}, queryErr
	}, func() time.Time { return current }, func(time.Duration) { t.Fatal("failed query must not wait") })
	if !errors.Is(err, errProbeAdapterAbsenceDeadline) || !errors.Is(err, queryErr) || !errors.Is(err, recordErr) {
		t.Fatal("deadline check hid underlying errors", err)
	}
}
