//go:build !darwin && !linux && !windows

package securefile

import (
	"errors"
	"time"
)

func Lock(string, time.Duration) (func(), error) {
	return nil, errors.New("native lifecycle locking is not enabled on this platform")
}
