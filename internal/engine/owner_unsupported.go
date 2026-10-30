//go:build !darwin && !windows

package engine

import "errors"

func validateOwner(string, Manifest) error {
	return errors.New("native run ownership unavailable on this platform")
}
func OwnerIdentity() (int, string, error) {
	return 0, "", errors.New("native run ownership unavailable on this platform")
}
