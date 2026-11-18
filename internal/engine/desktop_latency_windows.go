package engine

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func hideDesktopProbe(child *exec.Cmd) {
	child.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}
