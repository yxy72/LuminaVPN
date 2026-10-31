package engine

import (
	"os/exec"
	"syscall"
)

func hideVPNFixtureWindow(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} }
