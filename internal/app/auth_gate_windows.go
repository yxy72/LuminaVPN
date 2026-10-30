//go:build windows

package app

import (
	"errors"
	"netlaunch/internal/securefile"
	"path/filepath"
	"time"
)

func releaseAuthentication(marker string) error {
	return securefile.Bytes(filepath.Join(marker, "start"), []byte("ready\n"))
}
func awaitAuthentication(marker string) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, e := securefile.Read(filepath.Join(marker, "start"), 32, true); e == nil && string(b) == "ready\n" {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return errors.New("authentication console start gate expired")
}
