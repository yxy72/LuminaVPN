package winwfp

import (
	"netlaunch/internal/winnet"
	"testing"
)

func testSpec(t *testing.T) Spec {
	t.Helper()
	s, e := New(winnet.Adapter{Index: 7, LUID: 77, GUID: "vpn", Type: 53}, `C:\ProgramData\NetLaunch\run\netlaunch.exe`, []byte{1, 0, 0, 0})
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestGuardScopeAndIdentity(t *testing.T) {
	s := testSpec(t)
	for _, mutate := range []func(*Spec){
		func(s *Spec) { s.Adapter.Hardware = true },
		func(s *Spec) { s.Adapter.Type = 6 },
		func(s *Spec) { s.Adapter.LUID = 0 },
		func(s *Spec) { s.ForeignApp = s.Sublayer },
		func(s *Spec) { s.Executable = `relative.exe` },
		func(s *Spec) { s.AppID = []byte{1} },
	} {
		bad := s
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("unsafe guard accepted", bad)
		}
	}
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		x := testSpec(t)
		for _, k := range []string{x.Sublayer, x.ForeignApp, x.NonTCP, x.IPv6} {
			if seen[k] {
				t.Fatal("reused ownership key")
			}
			seen[k] = true
		}
	}
	if !Same(s, s) || Same(s, testSpec(t)) {
		t.Fatal("identity comparison")
	}
}
