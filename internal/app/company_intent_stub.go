//go:build !darwin

package app

import (
	"errors"
	"io"
)

func companyIntentEntry([]string, io.Writer) error {
	return errors.New("native macOS company intent is unavailable on this platform")
}
