//go:build !windows

package app

import (
	"os"
	"path/filepath"
)

func defaultProfilePath() (string, error) {
	p, e := os.UserConfigDir()
	if e != nil {
		return "", e
	}
	return filepath.Join(p, "NetLaunch"), nil
}
