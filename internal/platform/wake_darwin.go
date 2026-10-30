//go:build darwin

package platform

import (
	"fmt"
	"golang.org/x/sys/unix"
)

// WakeEpoch changes even when sleep resumes on the same SSID, interface and
// address. The boot component also invalidates persisted generations on reboot.
func WakeEpoch() (string, error) {
	boot, e := unix.SysctlTimeval("kern.boottime")
	if e != nil {
		return "", e
	}
	wake, e := unix.SysctlTimeval("kern.waketime")
	if e != nil {
		return "", e
	}
	return fmt.Sprintf("%d.%d/%d.%d", boot.Sec, boot.Usec, wake.Sec, wake.Usec), nil
}
