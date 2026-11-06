//go:build windows

package winnet

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestStrictPresenceRequiresAllIndependentAbsences(t *testing.T) {
	expected := Adapter{Index: 43, LUID: 12345, GUID: "{8B3AFCE7-975C-4164-A9B1-6B9BFBB4D032}", Name: "NL-TUN-fixture", Type: 53}
	for _, tc := range []struct {
		name        string
		row         bool
		down        bool
		reused      bool
		queryErr    error
		guidPresent bool
		want        string
	}{
		{"absent", false, false, false, nil, false, "absent"},
		{"down_row_is_present", true, true, false, nil, false, "present"},
		{"up_row_is_present", true, false, false, nil, false, "present"},
		{"index_reuse", true, false, true, nil, false, "conflict"},
		{"query_denied", false, false, false, windows.ERROR_ACCESS_DENIED, false, "unknown"},
		{"conversion_still_present", false, false, false, nil, true, "present"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var flags []uint32
			o, err := observeAdapterPresenceWith(expected, func(f uint32) ([]Adapter, error) {
				flags = append(flags, f)
				if tc.queryErr != nil {
					return nil, tc.queryErr
				}
				if !tc.row {
					return nil, nil
				}
				a := expected
				a.Up = !tc.down
				if tc.reused {
					a.GUID = "{F35839F4-83E4-4004-B370-F72DBB09B249}"
				}
				return []Adapter{a}, nil
			}, func(uint64, uint32) (Adapter, error) { return Adapter{}, windows.ERROR_FILE_NOT_FOUND }, func(string) (uint64, error) {
				if tc.guidPresent {
					return expected.LUID, nil
				}
				return 0, windows.ERROR_FILE_NOT_FOUND
			})
			if o.State != tc.want || len(flags) != 2 || flags[0] != 0 || flags[1] != 256 {
				t.Fatal(o.State, flags, err)
			}
			if (tc.want == "unknown" || tc.want == "conflict") != (err != nil) {
				t.Fatal("unknown/conflict was not a failure", err)
			}
		})
	}
	lookups := 0
	o, err := observeAdapterPresenceWith(expected, func(uint32) ([]Adapter, error) { return nil, nil }, func(l uint64, i uint32) (Adapter, error) {
		lookups++
		if l != 0 && i != 0 {
			t.Fatal("keys were collapsed")
		}
		return Adapter{}, errors.New("unknown native return")
	}, func(string) (uint64, error) { return 0, windows.ERROR_NOT_FOUND })
	if err == nil || o.State != "unknown" || lookups != 2 {
		t.Fatal("query error became absence", o, err)
	}
}
