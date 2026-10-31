package engine

import (
	"context"
	"errors"
	"time"
)

type terminalReadinessError struct{ error }

func (e *terminalReadinessError) Unwrap() error { return e.error }

// Checks must honor ctx for blocking work. A late success never overrides the
// stage deadline, even if a backend returns without observing cancellation.
func waitReady(ctx context.Context, limit time.Duration, pulse func() error, check func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	var last error
	for {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, last)
		}
		if err := pulse(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(err, last)
		}
		last = check(ctx)
		if err := ctx.Err(); err != nil {
			return errors.Join(err, last)
		}
		if last == nil {
			return nil
		}
		var terminal *terminalReadinessError
		if errors.As(last, &terminal) {
			return last
		}
		timer := time.NewTimer(300 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(ctx.Err(), last)
		case <-timer.C:
		}
	}
}
