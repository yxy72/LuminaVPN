//go:build darwin

package platform

import (
	"errors"
	"os"
	"syscall"
)

func deferPortBindCheck(e error) bool {
	// A user cannot bind privileged ports. A recently closed root listener can
	// also leave sockets that the user cannot reuse, even when root can do so.
	// Neither failure proves that the forthcoming root bind will fail.
	return os.Geteuid() != 0 && (errors.Is(e, syscall.EACCES) || errors.Is(e, syscall.EADDRINUSE))
}
