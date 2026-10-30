//go:build !darwin && !windows

package engine

import "errors"

func Internal(string, string) error {
	return errors.New("native lifecycle is not enabled on this platform")
}
func Launch(string, string) error { return errors.New("native lifecycle is enabled on macOS only") }

func ChildMain(string, int) error { return errors.New("native lifecycle is enabled on macOS only") }
