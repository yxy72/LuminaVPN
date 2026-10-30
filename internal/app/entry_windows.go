//go:build windows

package app

import (
	"errors"
	"netlaunch/internal/securefile"
	"path/filepath"
)

func stagedExecutableName() string { return "netlaunch.exe" }

// Resolve the directory at execution time. No user path is interpolated into
// batch source; quoted expansion with delayed expansion disabled preserves
// spaces, Unicode, percent signs, ampersands and exclamation marks in paths.
const windowsRecoveryEntry = `@echo off
setlocal DisableDelayedExpansion
for %%I in ("%~dp0.") do set "netlaunch_run=%%~fI"
"%netlaunch_run%\netlaunch.exe" down --run "%netlaunch_run%"
set "netlaunch_exit=%errorlevel%"
echo.
echo Recovery command finished. Exit code: %netlaunch_exit%
pause
exit /b %netlaunch_exit%
`

func writeRecoveryEntry(run, staged string) (string, error) {
	if staged != filepath.Join(run, stagedExecutableName()) {
		return "", errors.New("recovery executable must be staged beside entry")
	}
	path := filepath.Join(run, "恢复网络.cmd")
	if e := securefile.Bytes(path, []byte(windowsRecoveryEntry)); e != nil {
		return "", e
	}
	return path, nil
}

func sealStaged(path string) error { return securefile.ProtectFile(path) }
