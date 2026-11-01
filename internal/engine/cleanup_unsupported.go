//go:build !darwin && !windows

package engine

import "errors"

func CleanupRun(string, string, bool) (CleanupResult, error) {
	return CleanupResult{}, errors.New("native run cleanup unavailable")
}
