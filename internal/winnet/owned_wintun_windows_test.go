//go:build windows

package winnet

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func ownedWintunFixture(t *testing.T) (Adapter, windows.MibIfRow2) {
	t.Helper()
	guid, err := windows.GUIDFromString("{01234567-89AB-CDEF-0123-456789ABCDEF}")
	if err != nil {
		t.Fatal(err)
	}
	alias := "Lumina fixture"
	units, err := windows.UTF16FromString(alias)
	if err != nil {
		t.Fatal(err)
	}
	row := windows.MibIfRow2{
		InterfaceGuid: guid, InterfaceIndex: 5, InterfaceLuid: uint64(53)<<48 | uint64(42)<<24,
		Type: 53, OperStatus: windows.IfOperStatusDown,
	}
	copy(row.Alias[:], units)
	return Adapter{GUID: guid.String(), Index: row.InterfaceIndex, LUID: row.InterfaceLuid, Name: alias, Type: 53}, row
}

func TestOwnedWintunInstanceOnlyUsesFrozenVirtualGUID(t *testing.T) {
	expected, _ := ownedWintunFixture(t)
	instance, err := ownedWintunInstance(expected)
	if err != nil || !strings.EqualFold(instance, `SWD\WINTUN\`+expected.GUID) {
		t.Fatal("expected exact software device instance", err)
	}
	for _, mutate := range []func(*Adapter){
		func(a *Adapter) { a.GUID = "{00000000-0000-0000-0000-000000000000}" },
		func(a *Adapter) { a.LUID = uint64(6) << 48 },
		func(a *Adapter) { a.LUID |= 1 },
		func(a *Adapter) { a.Type = 6 },
		func(a *Adapter) { a.Hardware = true },
		func(a *Adapter) { a.Index = 0 },
		func(a *Adapter) { a.Name = "" },
	} {
		bad := expected
		mutate(&bad)
		if _, err := ownedWintunInstance(bad); err == nil {
			t.Fatal("invalid Wintun identity accepted")
		}
	}
}

func TestExactOwnedWintunDownRequiresAllCurrentSelectors(t *testing.T) {
	expected, row := ownedWintunFixture(t)
	var selectors [][2]uint64
	ready, err := exactOwnedWintunDown(expected, func(luid uint64, index uint32) (windows.MibIfRow2, error) {
		selectors = append(selectors, [2]uint64{luid, uint64(index)})
		return row, nil
	}, func(guid string) (uint64, error) {
		if guid != expected.GUID {
			t.Fatal("GUID query did not use frozen identity")
		}
		return expected.LUID, nil
	})
	if err != nil || !ready || len(selectors) != 2 ||
		selectors[0] != [2]uint64{expected.LUID, 0} || selectors[1] != [2]uint64{0, uint64(expected.Index)} {
		t.Fatal("exact Down identity not confirmed through all native selectors", err)
	}
	for _, tc := range []struct {
		name      string
		alter     func(*windows.MibIfRow2)
		lookupErr error
		guidLUID  uint64
		guidErr   error
		wantErr   bool
	}{
		{name: "running", alter: func(r *windows.MibIfRow2) { r.OperStatus = windows.IfOperStatusUp }},
		{name: "unknown status", alter: func(r *windows.MibIfRow2) { r.OperStatus = 4 }},
		{name: "interface vanished", lookupErr: windows.ERROR_NOT_FOUND},
		{name: "GUID vanished", guidErr: windows.ERROR_INVALID_PARAMETER},
		{name: "lookup failed", lookupErr: windows.ERROR_ACCESS_DENIED, wantErr: true},
		{name: "GUID lookup failed", guidErr: windows.ERROR_ACCESS_DENIED, wantErr: true},
		{name: "GUID moved", guidLUID: expected.LUID + 1, wantErr: true},
		{name: "alias changed", alter: func(r *windows.MibIfRow2) { r.Alias[0] = 'X' }, wantErr: true},
		{name: "index changed", alter: func(r *windows.MibIfRow2) { r.InterfaceIndex++ }, wantErr: true},
		{name: "hardware interface", alter: func(r *windows.MibIfRow2) { r.InterfaceAndOperStatusFlags = 1 }, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ready, err := exactOwnedWintunDown(expected, func(luid uint64, index uint32) (windows.MibIfRow2, error) {
				actual := row
				if index != 0 && tc.alter != nil {
					tc.alter(&actual)
				}
				return actual, tc.lookupErr
			}, func(string) (uint64, error) { return tc.guidLUID, tc.guidErr })
			if ready || (err != nil) != tc.wantErr {
				t.Fatalf("unexpected removal admission, ready=%v, err=%v", ready, err)
			}
		})
	}
}
