//go:build !windows

package desktopbridge

import (
	"os/signal"
	"syscall"
)

// Only the desktop entry ignores SIGPIPE; the existing CLI keeps its behavior.
func ignoreBrokenPipe() { signal.Ignore(syscall.SIGPIPE) }
