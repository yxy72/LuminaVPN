//go:build !darwin

package engine

import "context"

func LaunchContext(ctx context.Context, action, run string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return Launch(action, run)
}
