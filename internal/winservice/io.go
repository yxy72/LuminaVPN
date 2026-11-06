package winservice

import (
	"context"
	"errors"
	"time"
)

// pendingIO makes the cancellation/drain ordering testable without a Windows
// handle. The owner keeps data, OVERLAPPED and event alive until this returns.
type pendingIO interface {
	Wait() (bool, error)
	Complete() error
	CancelAndDrain() error
}

func finishPending(ctx context.Context, expired func() bool, io pendingIO) error {
	for {
		if ctx.Err() != nil {
			return errors.Join(ctx.Err(), io.CancelAndDrain())
		}
		if expired() {
			return errors.Join(context.DeadlineExceeded, io.CancelAndDrain())
		}
		ready, err := io.Wait()
		if err != nil {
			return errors.Join(err, io.CancelAndDrain())
		}
		if ready {
			return io.Complete()
		}
	}
}

type deadlineIO interface{ SetDeadline(time.Time) error }

func setFrameDeadline(stream any) {
	if value, ok := stream.(deadlineIO); ok {
		_ = value.SetDeadline(time.Now().Add(5 * time.Second))
	}
}
