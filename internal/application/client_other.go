//go:build !windows || !windows_client

package application

import "netlaunch/internal/serviceprotocol"

func newDesktopClient() serviceprotocol.Client { return nil }

func desktopRecoveryEntry() (any, error) {
	return nil, unavailable("RECOVERY_UNAVAILABLE", "Installed service recovery is unavailable in this build.")
}
