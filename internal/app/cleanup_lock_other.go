//go:build !darwin

package app

import (
	"netlaunch/internal/securefile"
	"time"
)

func cleanupProfileLock(path string, timeout time.Duration) (func(), error) {
	return securefile.Lock(path, timeout)
}
