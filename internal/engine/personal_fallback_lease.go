//go:build darwin || windows

package engine

import (
	"context"
	"errors"
	"math"
	"time"

	"netlaunch/internal/personalroute"
)

const personalFallbackLeasePath = "/proxies/PERSONAL/lumina-fallback"

type fallbackLeaseOperation string

const (
	openFallbackLease  fallbackLeaseOperation = "open"
	renewFallbackLease fallbackLeaseOperation = "renew"
)

type fallbackLeaseState struct {
	Revision   string `json:"revision"`
	NowMS      int64  `json:"now_ms"`
	Active     bool   `json:"active"`
	DeadlineMS int64  `json:"deadline_ms"`
}

type fallbackLeaseUpdate struct {
	Revision   string                 `json:"revision"`
	Operation  fallbackLeaseOperation `json:"operation"`
	DeadlineMS int64                  `json:"deadline_ms"`
}

var errFallbackLeaseStateChanged = errors.New("automatic personal fallback lease state changed")

func setPersonalFallbackLease(ctx context.Context, run string, operation fallbackLeaseOperation, expiresAt time.Time) (time.Time, error) {
	return setFallbackLease(ctx, operation, expiresAt, func(work context.Context, method string, in, out any) error {
		return apiContext(work, run, method, personalFallbackLeasePath, in, out)
	})
}

func setFallbackLease(ctx context.Context, operation fallbackLeaseOperation, expiresAt time.Time, request func(context.Context, string, any, any) error) (time.Time, error) {
	ctx, cancel := context.WithDeadline(ctx, expiresAt)
	defer cancel()
	sentAt := time.Now()
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	var before fallbackLeaseState
	if err := request(ctx, "GET", nil, &before); err != nil {
		return time.Time{}, err
	}
	if before.Revision == "" || len(before.Revision) > 128 || before.NowMS < 0 ||
		before.Active && before.DeadlineMS <= before.NowMS || !before.Active && before.DeadlineMS != 0 {
		return time.Time{}, errors.New("automatic personal fallback lease observation is invalid")
	}
	if before.Active != (operation == renewFallbackLease) {
		return time.Time{}, errFallbackLeaseStateChanged
	}

	// Derive the core deadline from its already observed monotonic clock. Time
	// spent on GET or PUT can shorten the lease and cannot add to the proof.
	remainingMS := time.Until(expiresAt).Milliseconds()
	if remainingMS < 2 || remainingMS > personalroute.DefaultMaxAge.Milliseconds() || before.NowMS > math.MaxInt64-remainingMS {
		return time.Time{}, errors.New("automatic personal fallback proof deadline is invalid")
	}
	deadlineMS := before.NowMS + remainingMS
	if operation == renewFallbackLease && deadlineMS <= before.DeadlineMS {
		return time.Time{}, errFallbackLeaseStateChanged
	}
	var after fallbackLeaseState
	update := fallbackLeaseUpdate{before.Revision, operation, deadlineMS}
	if err := request(ctx, "PUT", update, &after); err != nil {
		var rejected *coreFailure
		if errors.As(err, &rejected) && rejected.status == 409 {
			return time.Time{}, errFallbackLeaseStateChanged
		}
		return time.Time{}, err
	}
	if !after.Active || after.Revision == "" || len(after.Revision) > 128 || after.Revision == before.Revision ||
		after.DeadlineMS != deadlineMS || after.NowMS < before.NowMS || after.NowMS >= deadlineMS {
		return time.Time{}, errors.New("automatic personal fallback lease readback mismatch")
	}
	// sentAt precedes the core's GET observation. Round down once more for
	// the core's millisecond resolution before reporting a conservative cutoff.
	readback := sentAt.Add(time.Duration(remainingMS-1) * time.Millisecond)
	if !time.Now().Before(readback) || ctx.Err() != nil {
		return time.Time{}, context.DeadlineExceeded
	}
	return readback, nil
}
