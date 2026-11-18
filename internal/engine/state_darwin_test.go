package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestDarwinServeClosesAuthorizationPipesBeforeCoordinatorExits(t *testing.T) {
	run := t.TempDir()
	coordinator := filepath.Join(run, "coordinator's fixture")
	script := "#!/bin/sh\nprintf '%s %s' \"$1\" \"$2\" > \"$3/started\"\n/bin/sleep 4\n"
	if err := os.WriteFile(coordinator, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", darwinLaunchCommand("serve", coordinator, run))
	cmd.WaitDelay = time.Second
	if _, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("serve held the authorization output open: %v", err)
	}

	marker := filepath.Join(run, "started")
	for {
		if started, err := os.ReadFile(marker); err == nil && string(started) == "_serve --run" {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("serve did not start the coordinator")
		case <-time.After(10 * time.Millisecond):
		}
	}
}
