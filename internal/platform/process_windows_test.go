//go:build windows

package platform

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
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

func TestNativeStopIdentityFixture(t *testing.T) {
	if os.Getenv("NETLAUNCH_IDENTITY_FIXTURE") == "1" {
		time.Sleep(15 * time.Second)
		os.Exit(0)
	}
}

func TestNativeStopIdentityRejectsStaleRecord(t *testing.T) {
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(exe, "-test.run=^TestNativeStopIdentityFixture$")
	cmd.Env = append(os.Environ(), "NETLAUNCH_IDENTITY_FIXTURE=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer cmd.Process.Kill()
	id, e := Process(cmd.Process.Pid)
	if e != nil || id.PID == 0 {
		t.Fatal("fixture unavailable", e)
	}
	for _, field := range []string{"birth", "executable", "owner"} {
		stale := id
		switch field {
		case "birth":
			stale.Birth = "stale-creation-time"
		case "executable":
			stale.Executable += ".replaced"
		case "owner":
			stale.OwnerSID = "S-1-5-18"
		}
		if e = StopIdentity(stale); e == nil {
			t.Fatal("stale record accepted", field)
		}
		actual, e := Process(id.PID)
		if e != nil || actual != id {
			t.Fatal("unowned identity was terminated", field, e)
		}
	}
	// Positive control prevents permission failures from masquerading as safety.
	if e = StopIdentity(id); e != nil {
		t.Fatal("owned process not stopped", e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("owned termination not observed")
	}
	actual, e := Process(id.PID)
	if e != nil || actual == id {
		t.Fatal("owned identity remains alive", e)
	}
}
