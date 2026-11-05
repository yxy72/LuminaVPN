//go:build windows

package main

import (
	"errors"
	"fmt"
	"netlaunch/internal/winnet"
	"os"
)

// Missing publication after a durable creation intent is uncertain even when
// the requested GUID currently has no row. A killed native CreateAdapter may
// still have asynchronous installation work outstanding. Preserve that failed
// run for review instead of weakening the complete-identity success barrier.
func confirmReleasedProbeAdapter(published, intent func() (winnet.Adapter, error), verify func(winnet.Adapter) error) error {
	expected, err := published()
	if err == nil {
		return verify(expected)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read published adapter identity: %w", err)
	}
	expected, err = intent()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} // creation was never authorized
	if err != nil {
		return fmt.Errorf("read adapter creation intent: %w", err)
	}
	return errors.Join(errors.New("adapter creation started without complete identity publication; removal remains unconfirmed"), verify(expected))
}
