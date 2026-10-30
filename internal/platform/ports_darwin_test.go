//go:build darwin

package platform

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestOnlyAmbiguousUserBindFailuresAreDeferred(t *testing.T) {
	for _, tc := range []struct {
		err      error
		deferred bool
	}{
		{syscall.EACCES, true}, {fmt.Errorf("bind: %w", syscall.EADDRINUSE), true},
		{syscall.EPERM, false}, {syscall.EINVAL, false}, {errors.New("unknown"), false},
	} {
		want := tc.deferred && os.Geteuid() != 0
		if deferPortBindCheck(tc.err) != want {
			t.Fatal(tc.err, want)
		}
	}
}

func TestNativeLowPortIsPendingNotAvailable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an ordinary user")
	}
	checks, failures := PreflightPorts([]int{81})
	if len(failures) != 0 || len(checks) != 1 || checks[0].Status != "requires_privileged_check" {
		t.Fatal(checks, failures)
	}
	if e := CheckPort(81); !errors.Is(e, syscall.EACCES) {
		t.Fatal("expected native permission denial", e)
	}
	t.Log("ordinary-user low-port denial is reported as pending; final bind still fails without authorization")
}

func TestDeferredBusyPortStillFailsFinalBind(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	checks, failures := PreflightPorts([]int{port})
	if os.Geteuid() != 0 {
		if len(failures) != 0 || checks[0].Status != "requires_privileged_check" {
			t.Fatal(checks, failures)
		}
	} else if len(failures) != 1 || checks[0].Status != "failed" {
		t.Fatal(checks, failures)
	}
	if e := CheckPort(port); !errors.Is(e, syscall.EADDRINUSE) {
		t.Fatal("final bind allowed occupied port", e)
	}
}

func TestInvalidPortCannotBeDeferred(t *testing.T) {
	checks, failures := PreflightPorts([]int{0, 65536})
	if len(failures) != 2 || checks[0].Status != "failed" || checks[1].Status != "failed" {
		t.Fatal(checks, failures)
	}
}
