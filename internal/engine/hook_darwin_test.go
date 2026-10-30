//go:build darwin

package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenConnectHookCommandPreservesLiteralPath(t *testing.T) {
	for _, folder := range []string{"Application Support", "App's Support $(false); #"} {
		t.Run(folder, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), folder)
			if e := os.Mkdir(dir, 0700); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(dir, "vpn-hook")
			if e := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'hook-complete'\n"), 0700); e != nil {
				t.Fatal(e)
			}
			// Matches OpenConnect 9.21 script_config_tun's execl(/bin/sh, -c, script).
			command := strings.TrimPrefix(vpnScriptOption(path), "--script=")
			out, e := exec.Command("/bin/sh", "-c", command).CombinedOutput()
			if e != nil || string(out) != "hook-complete" {
				t.Fatal(string(out), e)
			}
		})
	}
}
