//go:build !darwin && !windows

package app

import (
	"context"
	"errors"
	"netlaunch/internal/policy"
	"os"
	"os/exec"
)

func authenticationSupported() bool { return false }
func launchAuthWindow(options, string) (func(), error) {
	return nil, errors.New("native authentication unavailable")
}
func authenticationCommand(context.Context, string, policy.VPN) (*exec.Cmd, error) {
	return nil, errors.New("native authentication unavailable")
}
func authenticationConsole() (*os.File, *os.File, func(), error) {
	return nil, nil, nil, errors.New("native authentication unavailable")
}
