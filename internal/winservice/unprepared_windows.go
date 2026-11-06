//go:build windows

package winservice

import "errors"

func LoadUnpreparedBinding(profileID string) (Binding, error) {
	return loadUnpreparedRole(profileID, false)
}
func LoadRecoveryUnpreparedBinding(profileID string) (Binding, error) {
	return loadUnpreparedRole(profileID, true)
}
func loadUnpreparedRole(profileID string, recovery bool) (Binding, error) {
	if _, err := LoadInstallation(); err != nil {
		return Binding{}, err
	}
	binding, err := loadEnrolledBindingRole(profileID, recovery)
	if err != nil {
		return Binding{}, err
	}
	if binding.RunRef == "" || binding.PreparedRunID != "" || binding.SpecDigest != "" {
		return Binding{}, errors.New("exact unprepared binding required")
	}
	return binding, nil
}
