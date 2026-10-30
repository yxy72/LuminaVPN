//go:build windows

package platform

import (
	"os"
	"strings"
	"testing"
)

func TestNativeProcessIdentityReadOnly(t *testing.T) {
	a, e := Process(os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	b, e := Process(os.Getpid())
	if e != nil || a != b {
		t.Fatal("unstable process identity", e)
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	if a.PID != os.Getpid() || a.Birth == "" || a.OwnerSID == "" || !strings.EqualFold(a.Executable, exe) || a.Command != "" {
		t.Fatal("incomplete native identity")
	}
	if _, e = Process(-1); e == nil {
		t.Fatal("invalid pid")
	}
	if e = StopIdentity(Identity{PID: os.Getpid()}); e == nil {
		t.Fatal("incomplete termination identity")
	}
	if _, e = foreignOpenConnect(); e != nil {
		t.Fatal(e)
	}
}
