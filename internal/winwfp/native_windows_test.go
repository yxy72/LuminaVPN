//go:build windows

package winwfp

import (
	"os"
	"runtime"
	"testing"
	"unsafe"
)

// These tests do not open the filtering engine or change firewall state.
func TestNativeLayoutAndFilterScope(t *testing.T) {
	if e := checkABI(); e != nil {
		t.Fatal(e)
	}
	var f filter
	if unsafe.Offsetof(f.Weight) != 96 || unsafe.Offsetof(f.Conditions) != 120 || unsafe.Offsetof(f.Action) != 128 || unsafe.Offsetof(f.Context) != 152 || unsafe.Offsetof(f.ID) != 176 {
		t.Fatal("filter ABI offsets")
	}
	a, e := encode(testSpec(t))
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.KeepAlive(a)
	// Collection must not lose pointer-backed union payloads.
	runtime.GC()
	if a.conditions[0][0].Value.Data == 0 || a.conditions[0][1].Value.Data == 0 {
		t.Fatal("native pointer payload was lost")
	}
	for i, f := range a.filters {
		if !filterEqual(f, f) {
			t.Fatal("readback equality", i)
		}
		if f.Flags != 0 || f.Action.Type != 0x1001 || a.conditions[i][0].Key != interfaceKey || a.conditions[i][0].Match != 0 || *(*uint64)(a.conditions[i][0].Value.pointer()) != 77 {
			t.Fatal("incorrect adapter scope")
		}
		changed := f
		changed.Flags = 1
		if filterEqual(changed, f) {
			t.Fatal("external flag change accepted")
		}
	}
	if a.conditions[0][1].Match != 10 || a.conditions[0][1].Key != appKey || a.conditions[1][1].Match != 10 || a.conditions[1][1].Value.Data != 6 || a.filters[2].Layer != layer6 || len(a.conditions[2]) != 1 {
		t.Fatal("incorrect deny semantics")
	}
}
func TestNativeApplicationIdentityReadOnly(t *testing.T) {
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	s, e := Prepare(testSpec(t).Adapter, exe)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Validate(); e != nil {
		t.Fatal(e)
	}
	if len(s.AppID) < 4 || s.AppID[len(s.AppID)-1] != 0 || s.AppID[len(s.AppID)-2] != 0 {
		t.Fatal("missing native UTF16 terminator")
	}
}
