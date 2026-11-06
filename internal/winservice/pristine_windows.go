//go:build windows

package winservice

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// PristineOwnedRuns proves only the first-install empty case. Historical run
// directories, unexpected entries, read errors and reparse points are unsafe.
func PristineOwnedRuns(expected Binding) (bool, error) {
	return pristineOwnedRunsRole(expected, false)
}
func PristineRecoveryOwnedRuns(expected Binding) (bool, error) {
	return pristineOwnedRunsRole(expected, true)
}
func pristineOwnedRunsRole(expected Binding, recovery bool) (bool, error) {
	before, err := loadEnrolledBindingRole(expected.ProfileID, recovery)
	if err != nil {
		return false, err
	}
	if before != expected || before.RunRef != "" || before.PreparedRunID != "" {
		return false, errors.New("owned run is not pristine")
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return false, err
	}
	root := filepath.Join(base, "LuminaVPN", "ServiceState")
	files := WindowsProtectedFiles{Root: root}
	runs := filepath.Join(root, "runs")
	if err = files.validatePath(runs); err != nil {
		return false, err
	}
	profile := filepath.Join(runs, expected.ProfileID)
	info, err := os.Lstat(profile)
	if err == nil {
		if err = files.validatePath(profile); err != nil {
			return false, err
		}
		if !info.IsDir() {
			return false, errors.New("unknown owned run entry")
		}
		entries, readErr := os.ReadDir(profile)
		if readErr != nil {
			return false, readErr
		}
		if len(entries) != 0 {
			return false, errors.New("historical owned runs require exact recovery proof")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	after, err := loadEnrolledBindingRole(expected.ProfileID, recovery)
	if err != nil {
		return false, err
	}
	if after != before {
		return false, errors.New("owned binding changed during empty-state proof")
	}
	return true, nil
}
