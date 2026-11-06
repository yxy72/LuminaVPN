//go:build windows

package winservice

import (
	"errors"
	"io/fs"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// The public preflight only reads native registry objects and the fixed file.
// Execution remains installer-owned; no registry string becomes a Go command.
func legacyUninstallPreflight(root string) error {
	return checkLegacyUninstall(root, windowsLegacyRegistry{}, func(path string) error {
		err := (WindowsProtectedFiles{Root: root}).validatePath(path)
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		base, knownErr := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
		if knownErr != nil {
			return knownErr
		}
		journal, exists, readErr := readResumeInstallerJournal(filepath.Join(base, "LuminaVPN", "ServiceState"))
		if checkErr := missingLegacyImagePreflight(journal, exists, readErr); checkErr != nil {
			return checkErr
		}
		return err
	})
}
