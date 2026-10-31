package app

import (
	"errors"
	"time"
)

func homeSessionTimeout(requested time.Duration) (time.Duration, error) {
	if requested == 0 {
		return 8 * time.Hour, nil
	}
	if requested < time.Second || requested > 12*time.Hour {
		return 0, errors.New("session timeout must be between 1s and 12h")
	}
	return requested, nil
}
