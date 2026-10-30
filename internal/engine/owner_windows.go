//go:build windows

package engine

import (
	"errors"
	"golang.org/x/sys/windows"
	"netlaunch/internal/securefile"
)

func OwnerIdentity() (int, string, error) {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return 0, "", e
	}
	if u.User.Sid == nil {
		return 0, "", errors.New("missing current user SID")
	}
	return 0, u.User.Sid.String(), nil
}
func validateOwner(run string, m Manifest) error {
	_, sid, e := OwnerIdentity()
	if e != nil {
		return e
	}
	if m.Owner != 0 || m.OwnerSID == "" || m.OwnerSID != sid {
		return errors.New("Windows run requires authorization by the same user who prepared it")
	}
	return securefile.CheckDir(run)
}
