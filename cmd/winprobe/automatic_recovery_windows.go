//go:build windows

package main

import "errors"

// Retrying can finish resource cleanup, but cannot erase a failed bounded
// attempt's validation outcome. In particular, killing a stuck holder never
// becomes a clean automatic close just because the next query finds it gone.
func runAutomaticRecoveryAttempts(recover func() error, recordFailure func(int, error) error, pause func()) (resourcesRecovered bool, validationErr error) {
	for attempt := 1; attempt <= 2; attempt++ {
		err := recover()
		if err == nil {
			return true, validationErr
		}
		validationErr = errors.Join(validationErr, err, recordFailure(attempt, err))
		// Optional failure-report I/O may fail validation, but it must not
		// prevent the second ownership-checked cleanup attempt.
		if attempt == 1 {
			pause()
		}
	}
	return false, validationErr
}
