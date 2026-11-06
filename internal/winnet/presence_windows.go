//go:build windows

package winnet

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type PresenceLookup struct {
	State   string   `json:"state"`
	Code    uint32   `json:"code"`
	Adapter *Adapter `json:"adapter,omitempty"`
	LUID    uint64   `json:"luid,omitempty"`
}
type PresenceEnumeration struct {
	Flags    uint32    `json:"flags"`
	Code     uint32    `json:"code"`
	Matching []Adapter `json:"matching"`
}
type AdapterPresence struct {
	State        string                `json:"state"`
	Expected     Adapter               `json:"expected"`
	StartedAt    time.Time             `json:"started_at"`
	FinishedAt   time.Time             `json:"finished_at"`
	Enumerations []PresenceEnumeration `json:"enumerations"`
	ByLUID       PresenceLookup        `json:"by_luid"`
	ByIndex      PresenceLookup        `json:"by_index"`
	ByGUID       PresenceLookup        `json:"by_guid"`
}

func validPresenceIdentity(a Adapter) error {
	g, err := windows.GUIDFromString(a.GUID)
	if err != nil || g == (windows.GUID{}) || a.Index == 0 || a.LUID == 0 || a.Name == "" || a.Type != 53 || a.Hardware {
		return errors.New("complete owned Wintun identity required")
	}
	return nil
}
func samePresenceIdentity(a, b Adapter) bool {
	return a.Index == b.Index && a.LUID == b.LUID && strings.EqualFold(a.GUID, b.GUID) && a.Name == b.Name && a.Type == b.Type && a.Hardware == b.Hardware
}
func presenceCollision(a, b Adapter) bool {
	return a.Index == b.Index || a.LUID == b.LUID || strings.EqualFold(a.GUID, b.GUID) || a.Name == b.Name
}
func presenceCode(err error) uint32 {
	if err == nil {
		return 0
	}
	var code windows.Errno
	if errors.As(err, &code) {
		return uint32(code)
	}
	return ^uint32(0)
}
func presenceNotFound(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_NOT_FOUND)
}

// Two raw GAA snapshots and independent LUID/index/GUID queries deliberately
// do not collapse Down rows, API errors, identity reuse or inconsistent views
// into absence. This is the client form of winprobe's strict presence gate.
func observeAdapterPresenceWith(expected Adapter, enumerate func(uint32) ([]Adapter, error), lookup func(uint64, uint32) (Adapter, error), convert func(string) (uint64, error)) (AdapterPresence, error) {
	o := AdapterPresence{State: "unknown", Expected: expected, StartedAt: time.Now(), Enumerations: []PresenceEnumeration{}}
	if err := validPresenceIdentity(expected); err != nil {
		o.FinishedAt = time.Now()
		return o, err
	}
	var failures []error
	present, conflict := false, false
	check := func(a Adapter) {
		if !samePresenceIdentity(expected, a) {
			conflict = true
		} else {
			present = true
		}
	}
	for _, flags := range []uint32{0, windows.GAA_FLAG_INCLUDE_ALL_INTERFACES} {
		rows, err := enumerate(flags)
		e := PresenceEnumeration{Flags: flags, Code: presenceCode(err), Matching: []Adapter{}}
		if err != nil {
			failures = append(failures, fmt.Errorf("GAA flags %d: %w", flags, err))
		}
		for _, a := range rows {
			if presenceCollision(expected, a) {
				e.Matching = append(e.Matching, a)
				check(a)
			}
		}
		if len(e.Matching) > 1 {
			conflict = true
		}
		o.Enumerations = append(o.Enumerations, e)
	}
	get := func(luid uint64, index uint32) PresenceLookup {
		a, err := lookup(luid, index)
		if presenceNotFound(err) {
			return PresenceLookup{State: "absent", Code: presenceCode(err)}
		}
		if err != nil {
			failures = append(failures, err)
			return PresenceLookup{State: "unknown", Code: presenceCode(err)}
		}
		check(a)
		return PresenceLookup{State: "present", Adapter: &a}
	}
	o.ByLUID, o.ByIndex = get(expected.LUID, 0), get(0, expected.Index)
	luid, err := convert(expected.GUID)
	switch {
	case presenceNotFound(err):
		o.ByGUID = PresenceLookup{State: "absent", Code: presenceCode(err)}
	case err != nil:
		failures = append(failures, err)
		o.ByGUID = PresenceLookup{State: "unknown", Code: presenceCode(err)}
	case luid == 0:
		failures = append(failures, errors.New("GUID conversion returned zero LUID"))
		o.ByGUID = PresenceLookup{State: "unknown"}
	default:
		present = true
		o.ByGUID = PresenceLookup{State: "present", LUID: luid}
		if luid != expected.LUID {
			conflict = true
		}
	}
	o.FinishedAt = time.Now()
	if conflict {
		o.State = "conflict"
		return o, errors.Join(append(failures, errors.New("owned adapter identity conflict"))...)
	}
	if len(failures) != 0 {
		return o, errors.Join(failures...)
	}
	if present {
		o.State = "present"
		return o, nil
	}
	if o.ByLUID.State == "absent" && o.ByIndex.State == "absent" && o.ByGUID.State == "absent" {
		o.State = "absent"
		return o, nil
	}
	return o, errors.New("owned adapter absence was not established")
}

func rawPresenceAdapters(flags uint32) ([]Adapter, error) {
	size := uint32(16 << 10)
	for attempt := 0; attempt < 8; attempt++ {
		if size > 16<<20 {
			return nil, errors.New("presence adapter table exceeded limit")
		}
		buf := make([]byte, size)
		head := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, head, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if errors.Is(err, windows.ERROR_NO_DATA) {
			return []Adapter{}, nil
		}
		if err != nil {
			return nil, err
		}
		var result []Adapter
		for p := head; p != nil; p = p.Next {
			guid := windows.BytePtrToString(p.AdapterName)
			result = append(result, Adapter{Index: p.IfIndex, LUID: p.Luid, GUID: guid, Name: windows.UTF16PtrToString(p.FriendlyName), Type: p.IfType, Up: p.OperStatus == windows.IfOperStatusUp})
		}
		runtime.KeepAlive(buf)
		return result, nil
	}
	return nil, errors.New("presence adapter table changed repeatedly")
}
func presenceLookup(luid uint64, index uint32) (Adapter, error) {
	row := windows.MibIfRow2{InterfaceLuid: luid, InterfaceIndex: index}
	if err := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row); err != nil {
		return Adapter{}, err
	}
	return Adapter{Index: row.InterfaceIndex, LUID: row.InterfaceLuid, GUID: row.InterfaceGuid.String(), Name: windows.UTF16ToString(row.Alias[:]), Type: row.Type, Hardware: row.InterfaceAndOperStatusFlags&1 != 0, Up: row.OperStatus == windows.IfOperStatusUp}, nil
}
func presenceGUIDLUID(s string) (uint64, error) {
	g, err := windows.GUIDFromString(s)
	if err != nil {
		return 0, err
	}
	var luid uint64
	raw, _, _ := ipHelper.NewProc("ConvertInterfaceGuidToLuid").Call(uintptr(unsafe.Pointer(&g)), uintptr(unsafe.Pointer(&luid)))
	if code := windows.Errno(uint32(raw)); code != 0 {
		return 0, code
	}
	if luid == 0 {
		return 0, errors.New("GUID conversion returned empty LUID")
	}
	return luid, nil
}
func ObserveAdapterPresence(expected Adapter) (AdapterPresence, error) {
	return observeAdapterPresenceWith(expected, rawPresenceAdapters, presenceLookup, presenceGUIDLUID)
}
func WaitAdapterAbsent(expected Adapter, limit time.Duration) (AdapterPresence, error) {
	if limit <= 0 || limit > 10*time.Second {
		return AdapterPresence{State: "unknown", Expected: expected}, errors.New("absence limit must be positive and at most 10 seconds")
	}
	deadline := time.Now().Add(limit)
	for {
		o, err := ObserveAdapterPresence(expected)
		if !time.Now().Before(deadline) {
			return o, errors.Join(err, errors.New("owned adapter absence deadline reached"))
		}
		if err != nil || o.State == "absent" {
			return o, err
		}
		if o.State != "present" {
			return o, errors.New("owned adapter presence unknown")
		}
		time.Sleep(min(100*time.Millisecond, time.Until(deadline)))
	}
}
