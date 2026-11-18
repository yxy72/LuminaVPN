//go:build !darwin && !windows

package securefile

import "os"

func openBoundedRead(path string) (*os.File, error) { return os.Open(path) }
