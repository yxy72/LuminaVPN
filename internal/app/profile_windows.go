//go:build windows

package app

import "netlaunch/internal/securefile"

func defaultProfilePath() (string, error) { return securefile.ProfilePath() }
