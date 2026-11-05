//go:build windows

package main

import (
	"errors"
	"fmt"
	"netlaunch/internal/winnet"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	probeAdapterPresent  = "present"
	probeAdapterAbsent   = "absent"
	probeAdapterConflict = "conflict"
	probeAdapterUnknown  = "unknown"
)

type adapterLookup struct {
	State   string          `json:"state"`
	Adapter *winnet.Adapter `json:"adapter,omitempty"`
	Error   string          `json:"error,omitempty"`
	LUID    uint64          `json:"luid,omitempty"`
}

// Rows contains only identities colliding with this run, never the unrelated
// adapter table. A failed query is unknown, never evidence of absence.
type adapterObservation struct {
	State            string           `json:"state"`
	Expected         winnet.Adapter   `json:"expected"`
	Rows             []winnet.Adapter `json:"matching_rows"`
	EnumerationError string           `json:"enumeration_error,omitempty"`
	ByLUID           adapterLookup    `json:"by_luid"`
	ByIndex          adapterLookup    `json:"by_index"`
	ByGUID           adapterLookup    `json:"by_guid"`
}

func sameProbeAdapterIdentity(a, b winnet.Adapter) bool {
	return a.Index == b.Index && a.LUID == b.LUID && a.GUID == b.GUID && a.Name == b.Name && a.Type == b.Type && a.Hardware == b.Hardware
}

func validProbeAdapterIdentity(a winnet.Adapter) error {
	guid, e := windows.GUIDFromString(a.GUID)
	intent := a.Index == 0 && a.LUID == 0
	if (a.Index == 0) != (a.LUID == 0) || a.Name == "" || e != nil || guid == (windows.GUID{}) || a.Hardware || (!intent && a.Type != 53) || (intent && a.Type != 0 && a.Type != 53) {
		return errors.New("missing or invalid published probe adapter identity")
	}
	return nil
}

func probeAdapterIdentityCollides(expected, actual winnet.Adapter) bool {
	return actual.Index == expected.Index || actual.LUID == expected.LUID || actual.GUID == expected.GUID || actual.Name == expected.Name
}

func lookupProbeAdapter(luid uint64, index uint32) (winnet.Adapter, error) {
	row := windows.MibIfRow2{InterfaceLuid: luid, InterfaceIndex: index}
	if e := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row); e != nil {
		return winnet.Adapter{}, e
	}
	return winnet.Adapter{
		Index: row.InterfaceIndex, LUID: row.InterfaceLuid,
		GUID: row.InterfaceGuid.String(), Name: windows.UTF16ToString(row.Alias[:]),
		Type: row.Type, Hardware: row.InterfaceAndOperStatusFlags&1 != 0,
		Up: row.OperStatus == windows.IfOperStatusUp,
	}, nil
}

func queryProbeAdapter(expected winnet.Adapter) (adapterObservation, error) {
	if expected.Index == 0 && expected.LUID == 0 {
		return queryProbeAdapterIntentWith(expected, winnet.Adapters, probeAdapterGUIDToLUID, lookupProbeAdapter)
	}
	return queryProbeAdapterWith(expected, winnet.Adapters, lookupProbeAdapter)
}

var probeAdapterIPHelper = windows.NewLazySystemDLL("iphlpapi.dll")

func probeAdapterGUIDToLUID(s string) (uint64, error) {
	guid, e := windows.GUIDFromString(s)
	if e != nil {
		return 0, e
	}
	var luid uint64
	code, _, _ := probeAdapterIPHelper.NewProc("ConvertInterfaceGuidToLuid").Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&luid)))
	if code != 0 {
		return 0, windows.Errno(code)
	}
	if luid == 0 {
		return 0, errors.New("native GUID conversion returned an empty LUID")
	}
	return luid, nil
}

// A durable requested-GUID intent precedes CreateAdapter, which can be
// interrupted before it returns a LUID/index. It identifies only that GUID
// and unique name; neither a same-name replacement nor an API failure is absent.
func queryProbeAdapterIntentWith(expected winnet.Adapter, enumerate func() ([]winnet.Adapter, error), convert func(string) (uint64, error), lookup func(uint64, uint32) (winnet.Adapter, error)) (adapterObservation, error) {
	o := adapterObservation{State: probeAdapterUnknown, Expected: expected, Rows: []winnet.Adapter{}, ByLUID: adapterLookup{State: "not_queried"}, ByIndex: adapterLookup{State: "not_queried"}}
	if e := validProbeAdapterIdentity(expected); e != nil {
		return o, e
	}
	if expected.Index != 0 || expected.LUID != 0 {
		return o, errors.New("requested-GUID observation requires an unpublished LUID/index")
	}
	var queryErrors []error
	rows, e := enumerate()
	if e != nil {
		o.EnumerationError = e.Error()
		queryErrors = append(queryErrors, fmt.Errorf("enumerate probe adapter intent: %w", e))
	}
	present := false
	var conflicts []string
	check := func(a winnet.Adapter) {
		if a.GUID != expected.GUID || a.Name != expected.Name || a.Index == 0 || a.LUID == 0 || a.Type != 53 || a.Hardware {
			conflicts = append(conflicts, "requested GUID/name identity reuse")
		} else {
			present = true
		}
	}
	for _, row := range rows {
		if row.GUID == expected.GUID || row.Name == expected.Name {
			o.Rows = append(o.Rows, row)
			check(row)
		}
	}
	if len(o.Rows) > 1 {
		conflicts = append(conflicts, "multiple colliding enumeration rows")
	}
	luid, conversionErr := convert(expected.GUID)
	switch {
	case errors.Is(conversionErr, windows.ERROR_FILE_NOT_FOUND) || errors.Is(conversionErr, windows.ERROR_NOT_FOUND):
		o.ByGUID = adapterLookup{State: probeAdapterAbsent}
	case conversionErr != nil:
		o.ByGUID = adapterLookup{State: probeAdapterUnknown, Error: conversionErr.Error()}
		queryErrors = append(queryErrors, fmt.Errorf("convert requested probe GUID: %w", conversionErr))
	case luid == 0:
		o.ByGUID = adapterLookup{State: probeAdapterUnknown, Error: "empty native LUID"}
		queryErrors = append(queryErrors, errors.New("requested probe GUID conversion returned an empty LUID"))
	default:
		present = true
		o.ByGUID = adapterLookup{State: probeAdapterPresent, LUID: luid}
		for _, row := range o.Rows {
			if row.LUID != luid {
				conflicts = append(conflicts, "GUID enumeration/conversion LUID disagreement")
			}
		}
		a, lookupErr := lookup(luid, 0)
		switch {
		case errors.Is(lookupErr, windows.ERROR_FILE_NOT_FOUND) || errors.Is(lookupErr, windows.ERROR_NOT_FOUND):
			// A GUID still maps to a LUID: a later snapshot must confirm the
			// conversion itself is absent before recovery may succeed.
			o.ByLUID = adapterLookup{State: probeAdapterAbsent}
		case lookupErr != nil:
			o.ByLUID = adapterLookup{State: probeAdapterUnknown, Error: lookupErr.Error()}
			queryErrors = append(queryErrors, fmt.Errorf("query requested probe LUID: %w", lookupErr))
		default:
			o.ByLUID = adapterLookup{State: probeAdapterPresent, Adapter: &a}
			check(a)
			if a.LUID != luid {
				conflicts = append(conflicts, "GUID/LUID conversion identity reuse")
			}
			for _, row := range o.Rows {
				if !sameProbeAdapterIdentity(row, a) {
					conflicts = append(conflicts, "GUID enumeration/native identity disagreement")
				}
			}
		}
	}
	if len(conflicts) != 0 {
		o.State = probeAdapterConflict
		return o, errors.Join(append(queryErrors, fmt.Errorf("probe adapter intent conflict: %s", strings.Join(conflicts, "; ")))...)
	}
	if len(queryErrors) != 0 {
		return o, errors.Join(queryErrors...)
	}
	if present {
		o.State = probeAdapterPresent
		return o, nil
	}
	if len(o.Rows) == 0 && o.ByGUID.State == probeAdapterAbsent {
		o.State = probeAdapterAbsent
		return o, nil
	}
	return o, errors.New("requested probe adapter absence was not established")
}

func queryProbeAdapterWith(expected winnet.Adapter, enumerate func() ([]winnet.Adapter, error), lookup func(uint64, uint32) (winnet.Adapter, error)) (adapterObservation, error) {
	o := adapterObservation{State: probeAdapterUnknown, Expected: expected, Rows: []winnet.Adapter{}}
	if e := validProbeAdapterIdentity(expected); e != nil {
		return o, e
	}
	if expected.Index == 0 || expected.LUID == 0 {
		return o, errors.New("complete probe adapter observation requires a published LUID/index")
	}
	rows, enumerationErr := enumerate()
	if enumerationErr != nil {
		o.EnumerationError = enumerationErr.Error()
	}
	for _, row := range rows {
		if probeAdapterIdentityCollides(expected, row) {
			o.Rows = append(o.Rows, row)
		}
	}
	var queryErrors []error
	if enumerationErr != nil {
		queryErrors = append(queryErrors, fmt.Errorf("enumerate probe adapter: %w", enumerationErr))
	}
	get := func(luid uint64, index uint32) adapterLookup {
		a, e := lookup(luid, index)
		if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) || errors.Is(e, windows.ERROR_NOT_FOUND) {
			return adapterLookup{State: probeAdapterAbsent}
		}
		if e != nil {
			queryErrors = append(queryErrors, fmt.Errorf("query probe adapter LUID=%d index=%d: %w", luid, index, e))
			return adapterLookup{State: probeAdapterUnknown, Error: e.Error()}
		}
		return adapterLookup{State: probeAdapterPresent, Adapter: &a}
	}
	// Query each key independently: supplying both would let a preferred key
	// hide an interface-index reuse or a disagreement between the native APIs.
	o.ByLUID = get(expected.LUID, 0)
	o.ByIndex = get(0, expected.Index)
	present := false
	var conflicts []string
	for _, row := range o.Rows {
		if !sameProbeAdapterIdentity(expected, row) {
			conflicts = append(conflicts, "enumeration identity/name reuse")
		} else {
			present = true
		}
	}
	if len(o.Rows) > 1 {
		conflicts = append(conflicts, "multiple colliding enumeration rows")
	}
	for _, item := range []struct {
		name string
		data adapterLookup
	}{{"LUID", o.ByLUID}, {"index", o.ByIndex}} {
		if item.data.Adapter == nil {
			continue
		}
		if !sameProbeAdapterIdentity(expected, *item.data.Adapter) {
			conflicts = append(conflicts, item.name+" identity/name reuse")
		} else {
			present = true
		}
	}
	if len(conflicts) != 0 {
		o.State = probeAdapterConflict
		return o, errors.Join(append(queryErrors, fmt.Errorf("probe adapter identity conflict: %s", strings.Join(conflicts, "; ")))...)
	}
	if len(queryErrors) != 0 {
		return o, errors.Join(queryErrors...)
	}
	if present {
		// Exact rows may disappear between these separate snapshots. Any exact
		// row, including a Down row, prevents an absence claim and is retried.
		o.State = probeAdapterPresent
		return o, nil
	}
	if len(o.Rows) == 0 && o.ByLUID.State == probeAdapterAbsent && o.ByIndex.State == probeAdapterAbsent {
		o.State = probeAdapterAbsent
		return o, nil
	}
	return o, errors.New("probe adapter absence was not established")
}

func waitProbeAdapterAbsent(expected winnet.Adapter, timeout time.Duration, observe func(adapterObservation) error) (adapterObservation, error) {
	return waitProbeAdapterAbsentWith(expected, timeout, observe, queryProbeAdapter, time.Now, time.Sleep)
}

var errProbeAdapterAbsenceDeadline = errors.New("probe adapter absence was not confirmed before deadline")

func waitProbeAdapterAbsentWith(expected winnet.Adapter, timeout time.Duration, observe func(adapterObservation) error, query func(winnet.Adapter) (adapterObservation, error), now func() time.Time, sleep func(time.Duration)) (adapterObservation, error) {
	last := adapterObservation{State: probeAdapterUnknown, Expected: expected}
	if timeout <= 0 || timeout > 10*time.Second {
		return last, errors.New("probe adapter disappearance timeout must be positive and at most 10s")
	}
	if e := validProbeAdapterIdentity(expected); e != nil {
		return last, e
	}
	deadline := now().Add(timeout)
	previousState := ""
	for {
		var e error
		last, e = query(expected)
		queryExpired := !now().Before(deadline)
		var recordErr error
		if observe != nil && (last.State != previousState || e != nil) {
			if recordErr = observe(last); recordErr != nil {
				recordErr = fmt.Errorf("record probe adapter observation: %w", recordErr)
			}
		}
		previousState = last.State
		// Querying and recording are part of the same absolute bound. A row
		// first reported absent at the deadline (or later) cannot pass, nor
		// can a timely query whose observer completes after the deadline.
		remaining := deadline.Sub(now())
		if queryExpired || remaining <= 0 {
			return last, errors.Join(e, recordErr, errProbeAdapterAbsenceDeadline)
		}
		if e != nil || recordErr != nil {
			return last, errors.Join(e, recordErr)
		}
		if last.State == probeAdapterAbsent {
			return last, nil
		}
		if last.State != probeAdapterPresent {
			return last, fmt.Errorf("cannot confirm probe adapter disappearance: %s", last.State)
		}
		if remaining > 100*time.Millisecond {
			remaining = 100 * time.Millisecond
		}
		sleep(remaining)
	}
}
