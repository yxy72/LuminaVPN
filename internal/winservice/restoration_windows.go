//go:build windows

package winservice

import (
	"errors"
	"golang.org/x/sys/windows"
	"path/filepath"
)

func OpenRestorationStore(binding Binding) (*RestorationStore, error) {
	return openRestorationStoreRole(binding, false)
}
func OpenRecoveryRestorationStore(binding Binding) (*RestorationStore, error) {
	return openRestorationStoreRole(binding, true)
}
func openRestorationStoreRole(binding Binding, recovery bool) (*RestorationStore, error) {
	current, err := loadEnrolledBindingRole(binding.ProfileID, recovery)
	if err != nil || !sameEnrollment(current, binding) {
		return nil, errors.New("restoration enrollment unavailable")
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return nil, err
	}
	return &RestorationStore{files: installedStateFiles{root: filepath.Join(base, "LuminaVPN", "ServiceState")}, enrolled: binding}, nil
}
