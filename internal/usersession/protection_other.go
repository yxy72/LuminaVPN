//go:build !windows

package usersession

import "errors"

type nativeProtector struct{}

func (nativeProtector) Protect([]byte, []byte) ([]byte, error) {
	return nil, errors.New("Windows user protection unavailable")
}
func (nativeProtector) Unprotect([]byte, []byte) ([]byte, error) {
	return nil, errors.New("Windows user protection unavailable")
}
