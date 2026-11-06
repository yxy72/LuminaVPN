//go:build !windows

package app

import (
	"errors"
	"io"
)

func serviceHelperEntry([]string, io.Writer) error {
	return errors.New("Windows service helper unavailable on this platform")
}
