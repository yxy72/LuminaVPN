//go:build windows

// Package winprofile resolves the Windows client's user storage independently
// of a mutable home directory or environment-provided path.
package winprofile

import (
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

type Location struct {
	Root, UserDirectory, Profile string
	SID                          string
}

func locationAt(programData, sid string) (Location, error) {
	parsed, err := windows.StringToSid(sid)
	if err != nil || !parsed.IsValid() || parsed.String() != sid || !(strings.HasPrefix(sid, "S-1-5-21-") || strings.HasPrefix(sid, "S-1-12-1-")) {
		return Location{}, errors.New("native desktop user SID required")
	}
	if !filepath.IsAbs(programData) || filepath.Clean(programData) != programData || len(filepath.VolumeName(programData)) != 2 || strings.Contains(programData[2:], ":") {
		return Location{}, errors.New("native local ProgramData path required")
	}
	root := filepath.Join(programData, "LuminaVPN-Users")
	user := filepath.Join(root, sid)
	return Location{Root: root, UserDirectory: user, Profile: filepath.Join(user, ".netlaunch"), SID: sid}, nil
}

func LocationForSID(sid string) (Location, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return Location{}, err
	}
	return locationAt(base, sid)
}

func LocationForToken(token windows.Token) (Location, error) {
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return Location{}, errors.New("native token user unavailable")
	}
	return LocationForSID(user.User.Sid.String())
}

// PathForToken is read-only. Installation prepares the protected parent; the
// current user then creates the private profile using securefile primitives.
func PathForToken(token windows.Token) (string, error) {
	location, err := LocationForToken(token)
	return location.Profile, err
}
