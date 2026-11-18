//go:build !darwin && !windows

package engine

import (
	"context"
	"errors"

	"netlaunch/internal/policy"
)

func MeasureDesktopLatency(context.Context, string, string, []policy.Node, string) (map[string]int, error) {
	return nil, errors.New("isolated node measurement unavailable")
}
