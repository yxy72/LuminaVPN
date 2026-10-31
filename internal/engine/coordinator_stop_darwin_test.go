package engine

import (
	"os/exec"
	"testing"
	"time"

	"netlaunch/internal/platform"
)

// Native process-only fixture: no root access, routes, DNS or VPN are used.
func TestDarwinRecoveryStopsOnlyPublishedCoordinator(t *testing.T) {
	child := exec.Command("/bin/sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = child.Wait(); close(done) }()
	defer func() { _ = child.Process.Kill(); <-done }()
	id, err := platform.Process(child.Process.Pid)
	if err != nil || id.PID == 0 {
		t.Fatal("fixture identity unavailable", err)
	}
	changed := id
	changed.Command += " changed"
	if err := stopCoordinator(changed); err == nil {
		t.Fatal("changed identity was signalled")
	}
	changed = id
	changed.Birth += " changed"
	if err := stopCoordinator(changed); err != nil {
		t.Fatal("reused identity was not treated as already gone", err)
	}
	if actual, err := platform.Process(id.PID); err != nil || actual != id {
		t.Fatal("foreign identity check stopped original fixture", err)
	}
	if err := stopCoordinator(id); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("owned coordinator did not exit")
	}
}
