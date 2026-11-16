//go:build !darwin

package app

import (
	"context"
	"errors"
	"io"
)

func (*RunStop) SetMacCompany(context.Context, string, uint64, bool, bool) error {
	return errors.New("native macOS company intent is unavailable on this platform")
}

func companyIntentEntry([]string, io.Writer) error {
	return errors.New("native macOS company intent is unavailable on this platform")
}
