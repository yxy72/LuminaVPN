//go:build !darwin

package engine

import (
	"context"
	"errors"
)

func MacServiceProfileRun(profile, run string) bool { return false }

func PrepareMacServiceRun(context.Context, string, string) (string, error) {
	return "", errors.New("macOS network service is unavailable on this platform")
}

func DiscardMacServiceRun(context.Context, string) {}

func MacServiceCommand([]string) (bool, error) { return false, nil }
