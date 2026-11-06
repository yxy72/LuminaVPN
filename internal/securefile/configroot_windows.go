//go:build windows

package securefile

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"netlaunch/internal/winprofile"
)

var profileDir = syscall.NewLazyDLL("userenv.dll").NewProc("GetUserProfileDirectoryW")
var knownFolder = syscall.NewLazyDLL("shell32.dll").NewProc("SHGetKnownFolderPath")
var freeCOM = syscall.NewLazyDLL("ole32.dll").NewProc("CoTaskMemFree")
var duplicateToken = adv.NewProc("DuplicateToken")
var accessCheck = adv.NewProc("AccessCheck")

type guid struct {
	A    uint32
	B, C uint16
	D    [8]byte
}

func tokenForUser() (syscall.Token, error) {
	p, e := syscall.GetCurrentProcess()
	if e != nil {
		return 0, e
	}
	var t syscall.Token
	e = syscall.OpenProcessToken(p, syscall.TOKEN_QUERY|syscall.TOKEN_DUPLICATE, &t)
	return t, e
}
func configLocation(local bool) (string, string, error) {
	token, e := tokenForUser()
	if e != nil {
		return "", "", e
	}
	defer token.Close()
	profile, e := profileForToken(token)
	if e != nil {
		return "", "", e
	}
	id := guid{0x3eb685db, 0x65f9, 0x4cf6, [8]byte{0xa0, 0x3a, 0xe3, 0xef, 0x65, 0x72, 0x9f, 0x3d}}
	part := "Roaming"
	if local {
		id = guid{0xf1b32785, 0x6fba, 0x4fcf, [8]byte{0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15, 0x70, 0x91}}
		part = "Local"
	}
	var result *uint16
	hr, _, _ := knownFolder.Call(uintptr(unsafe.Pointer(&id)), 0, uintptr(token), uintptr(unsafe.Pointer(&result)))
	if int32(hr) < 0 {
		return "", "", fmt.Errorf("securefile: known folder HRESULT 0x%x", hr)
	}
	if result == nil {
		return "", "", errors.New("securefile: missing known folder")
	}
	defer freeCOM.Call(uintptr(unsafe.Pointer(result)))
	var chars []uint16
	for i := 0; i < 32768; i++ {
		v := *(*uint16)(unsafe.Add(unsafe.Pointer(result), i*2))
		if v == 0 {
			break
		}
		chars = append(chars, v)
	}
	app, e := cleanPath(syscall.UTF16ToString(chars))
	if e != nil {
		return "", "", e
	}
	if !strings.EqualFold(app, filepath.Join(profile, "AppData", part)) {
		return "", "", errors.New("securefile: redirected AppData unsupported")
	}
	return profile, filepath.Join(app, "NetLaunch"), nil
}
func safeParent(h syscall.Handle, user string) error {
	owner, dacl, sd, e := ownerAndDACL(h)
	if e != nil {
		return e
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	if owner == nil || dacl == nil {
		return errors.New("securefile: parent has NULL DACL or owner")
	}
	s, e := owner.String()
	if e != nil {
		return e
	}
	if !approved(s, user) {
		return errors.New("securefile: unsafe parent owner")
	}
	count := *(*uint16)(unsafe.Add(dacl, 4))
	for i := uint16(0); i < count; i++ {
		var ace unsafe.Pointer
		ok, _, e := getACE.Call(uintptr(dacl), uintptr(i), uintptr(unsafe.Pointer(&ace)))
		if e = winerr("parent GetAce", ok, e); e != nil {
			return e
		}
		header := unsafe.Slice((*byte)(ace), 8)
		if header[0] != 0 && header[0] != 1 {
			return errors.New("securefile: unsupported parent ACE")
		}
		if *(*uint16)(unsafe.Add(ace, 2)) < 16 {
			return errors.New("securefile: malformed parent ACE")
		}
		// Deny ACEs and inherit-only ACEs do not grant access to this parent.
		if header[0] == 1 || header[1]&8 != 0 {
			continue
		}
		sid := (*syscall.SID)(unsafe.Add(ace, 8))
		s, e = sid.String()
		if e != nil {
			return e
		}
		mask := *(*uint32)(unsafe.Add(ace, 4))
		if !approved(s, user) && mask&0x500d0156 != 0 {
			return errors.New("securefile: unapproved parent writer")
		}
	}
	return nil
}

// writableParent uses the effective process token (including deny-only groups)
// rather than inferring effective write rights from an allow ACE alone.
func writableParent(h syscall.Handle) error {
	var sd uintptr
	code, _, _ := getInfo.Call(uintptr(h), 1, 7, 0, 0, 0, 0, uintptr(unsafe.Pointer(&sd)))
	if code != 0 {
		return syscall.Errno(code)
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	token, e := tokenForUser()
	if e != nil {
		return e
	}
	defer token.Close()
	var imp syscall.Token
	ok, _, e := duplicateToken.Call(uintptr(token), 2, uintptr(unsafe.Pointer(&imp)))
	if e = winerr("DuplicateToken", ok, e); e != nil {
		return e
	}
	defer imp.Close()
	mapping := [4]uint32{0x120089, 0x120116, 0x1200a0, fullControl}
	privileges := make([]byte, 4096)
	size := uint32(len(privileges))
	var granted uint32
	var allowed int32
	ok, _, e = accessCheck.Call(sd, uintptr(imp), 4, uintptr(unsafe.Pointer(&mapping)), uintptr(unsafe.Pointer(&privileges[0])), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&granted)), uintptr(unsafe.Pointer(&allowed)))
	if e = winerr("AccessCheck", ok, e); e != nil {
		return e
	}
	if allowed == 0 || granted&4 == 0 {
		return errors.New("securefile: parent not writable by effective token")
	}
	return nil
}

// PrivateConfigRoot conservatively creates %APPDATA%\NetLaunch (local=false)
// or %LOCALAPPDATA%\NetLaunch (local=true). Locations come from the current
// process token and Known Folders, never environment variables. Redirected
// profiles/AppData, reparse points and unsafe parents fail closed. Parent ACLs
// are never changed. Existing roots are only verified, never repaired.
func PrivateConfigRoot(local bool) (string, error) {
	profile, path, e := configLocation(local)
	if e != nil {
		return "", e
	}
	return privateRoot(profile, path)
}

// PrivateProfileRoot creates only the fixed Windows client's profile below the
// installer-protected per-user namespace. Home/AppData ACLs are not changed or
// relied upon. Existing roots remain subject to strict private ACL validation;
// configuration is never silently migrated from a legacy location.
func PrivateProfileRoot() (string, error) {
	token, e := tokenForUser()
	if e != nil {
		return "", e
	}
	defer token.Close()
	location, release, e := winprofile.OpenForToken(windows.Token(token))
	if e != nil {
		return "", e
	}
	defer release()
	return privateRoot(location.UserDirectory, location.Profile)
}

// rootParents is read-only. profile is the native user trust boundary in public
// callers; tests substitute a freshly created, task-owned private directory.
func rootParents(profile, path string) (pins []syscall.Handle, user string, err error) {
	defer func() {
		if err != nil {
			closeAll(pins)
			pins = nil
		}
	}()
	profile, err = cleanPath(profile)
	if err != nil {
		return
	}
	path, err = cleanPath(path)
	if err != nil {
		return
	}
	if !strings.HasPrefix(strings.ToLower(path), strings.ToLower(profile)+`\`) {
		err = errors.New("securefile: root outside profile")
		return
	}
	user, err = currentSID()
	if err != nil {
		return
	}
	here := path[:3]
	var h syscall.Handle
	h, err = open(here, readControl)
	if err != nil {
		return
	}
	pins = append(pins, h)
	if err = shape(h, true); err != nil {
		return
	}
	parent := filepath.Dir(path)
	for _, part := range strings.Split(strings.TrimPrefix(parent, here), `\`) {
		here = filepath.Join(here, part)
		h, err = open(here, readControl)
		if err != nil {
			return
		}
		pins = append(pins, h)
		if err = shape(h, true); err != nil {
			return
		}
		if strings.EqualFold(here, profile) || strings.HasPrefix(strings.ToLower(here), strings.ToLower(profile)+`\`) {
			if err = safeParent(h, user); err != nil {
				return
			}
		}
	}
	err = writableParent(h)
	return
}
func privateRoot(profile, path string) (string, error) {
	pins, user, e := rootParents(profile, path)
	if e != nil {
		return "", e
	}
	defer func() { closeAll(pins) }()
	e = makeDir(path, user)
	if e != nil && !errors.Is(e, syscall.ERROR_ALREADY_EXISTS) {
		return "", e
	}
	h, e := open(path, readControl)
	if e != nil {
		return "", e
	}
	pins = append(pins, h)
	if e = shape(h, true); e != nil {
		return "", e
	}
	if e = checkACL(h, user); e != nil {
		return "", e
	}
	return path, nil
}

func profileForToken(token syscall.Token) (string, error) {
	b := make([]uint16, 32768)
	n := uint32(len(b))
	ok, _, e := profileDir.Call(uintptr(token), uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&n)))
	if e = winerr("GetUserProfileDirectory", ok, e); e != nil {
		return "", e
	}
	profile, e := cleanPath(syscall.UTF16ToString(b))
	if e != nil {
		return "", e
	}
	return profile, nil
}

func profileLocation() (string, error) {
	token, e := tokenForUser()
	if e != nil {
		return "", e
	}
	defer token.Close()
	return profileForToken(token)
}
