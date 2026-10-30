//go:build !windows

package app

import (
	"netlaunch/internal/securefile"
	"os"
	"path/filepath"
)

func stagedExecutableName() string { return "netlaunch" }
func writeRecoveryEntry(run, staged string) (string, error) {
	script := "#!/bin/sh\n" + quote(staged) + " down --run " + quote(run) + "\nrc=$?\nprintf '\\nRecovery command finished (exit %s). Press Enter to close.\\n' \"$rc\"\nread answer\nexit \"$rc\"\n"
	path := filepath.Join(run, "恢复网络.command")
	if e := securefile.Bytes(path, []byte(script)); e != nil {
		return "", e
	}
	if e := os.Chmod(path, 0700); e != nil {
		return "", e
	}
	return path, nil
}

func sealStaged(string) error { return nil }
