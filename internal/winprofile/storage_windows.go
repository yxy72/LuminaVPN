//go:build windows

package winprofile

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const privateFullControl = uint32(0x1f01ff)

func closeHandles(handles []windows.Handle) {
	for i := len(handles) - 1; i >= 0; i-- {
		windows.CloseHandle(handles[i])
	}
}

func openDirectory(path string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	// READ_CONTROL alone does not participate in Windows file share checks.
	// A data-read access bit is necessary for omitting FILE_SHARE_DELETE to
	// actually prevent namespace replacement while this handle is held.
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, err
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		windows.CloseHandle(h)
		return 0, errors.New("profile ancestor is redirected or not a directory")
	}
	resolved := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(h, &resolved[0], uint32(len(resolved)), 0)
	if err != nil || n == 0 || n >= uint32(len(resolved)) || !strings.EqualFold(windows.UTF16ToString(resolved[:n]), `\\?\`+path) {
		windows.CloseHandle(h)
		return 0, errors.New("profile directory handle is outside its fixed namespace")
	}
	return h, nil
}

func checkPinnedShapes(handles []windows.Handle) error {
	for _, h := range handles {
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return errors.New("profile ancestor changed into a redirected object")
		}
	}
	return nil
}

// pinExistingAnchor proves ProgramData cannot become empty while the new
// namespace is created. Attribute-only access is not controlled by file share
// flags and could otherwise turn an empty directory into a reparse point.
// A final-path-verified child held without delete sharing pins a real entry.
func pinExistingAnchor(parent string) (windows.Handle, error) {
	for _, name := range []string{"LuminaVPN-Setup", "Microsoft"} {
		h, err := openDirectory(filepath.Join(parent, name))
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if err = validateAncestor(h); err != nil {
			windows.CloseHandle(h)
			return 0, err
		}
		return h, nil
	}
	return 0, errors.New("ProgramData has no verified existing namespace anchor")
}

func pinAncestors(path string) ([]windows.Handle, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(filepath.VolumeName(path)) != 2 {
		return nil, errors.New("fixed local profile ancestor required")
	}
	root := filepath.VolumeName(path) + `\`
	var handles []windows.Handle
	current := root
	for _, part := range append([]string{""}, strings.Split(strings.TrimPrefix(path, root), `\`)...) {
		if part != "" {
			current = filepath.Join(current, part)
		}
		h, err := openDirectory(current)
		if err != nil {
			closeHandles(handles)
			return nil, err
		}
		handles = append(handles, h)
	}
	return handles, nil
}

func rootDescriptor() string {
	// Users can traverse and inspect ancestors for no-follow validation, but
	// cannot create, replace, rename or delete another user's storage directory.
	return "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
}

func userDescriptor(sid string) string {
	return "O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
}

func validateAncestor(handle windows.Handle) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil || !sd.IsValid() {
		return errors.New("profile namespace ancestor security unavailable")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("profile namespace ancestor owner unavailable")
	}
	trusted := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true}
	if installer, _, _, lookupErr := windows.LookupSID("", `NT SERVICE\TrustedInstaller`); lookupErr == nil {
		trusted[installer.String()] = true
	}
	if !trusted[owner.String()] {
		return errors.New("profile namespace ancestor has an untrusted owner")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount > 512 {
		return errors.New("profile namespace ancestor DACL unavailable")
	}
	const replace = uint32(0x10000000 | 64 | 0x10000 | 0x40000 | 0x80000)
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace == nil {
			return errors.New("unknown profile namespace ancestor ACE")
		}
		if ace.Header.AceFlags&8 != 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
			return errors.New("unclassified profile namespace ancestor ACE")
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceSize < 16 {
			return errors.New("truncated profile namespace ancestor ACE")
		}
		trustee := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trustee.IsValid() || trustee.Len() > int(ace.Header.AceSize)-8 {
			return errors.New("invalid profile namespace ancestor trustee")
		}
		if uint32(ace.Mask)&replace != 0 && !trusted[trustee.String()] {
			return errors.New("profile namespace ancestor is replaceable by an untrusted principal")
		}
	}
	runtime.KeepAlive(sd)
	return nil
}

func validateDirectory(handle windows.Handle, sid string, root bool) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil || !sd.IsValid() {
		return errors.New("profile parent security unavailable")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("profile parent owner unavailable")
	}
	ownerText := owner.String()
	if root && ownerText != "S-1-5-18" && ownerText != "S-1-5-32-544" || !root && ownerText != sid && ownerText != "S-1-5-18" && ownerText != "S-1-5-32-544" {
		return errors.New("profile parent has an unexpected owner")
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("profile parent requires a protected DACL")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 3 {
		return errors.New("profile parent requires the exact private ACL")
	}
	want := map[string]uint32{"S-1-5-18": privateFullControl, "S-1-5-32-544": privateFullControl}
	if root {
		want["S-1-5-32-545"] = 0x1200a9
	} else {
		want[sid] = privateFullControl
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 3 || ace.Header.AceSize < 16 {
			return errors.New("unexpected profile parent ACE")
		}
		trustee := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trustee.IsValid() || trustee.Len() > int(ace.Header.AceSize)-8 {
			return errors.New("invalid profile parent trustee")
		}
		mask, exists := want[trustee.String()]
		if !exists || uint32(ace.Mask) != mask {
			return errors.New("profile parent ACL differs from the installer contract")
		}
		delete(want, trustee.String())
	}
	runtime.KeepAlive(sd)
	if len(want) != 0 {
		return errors.New("incomplete profile parent ACL")
	}
	return nil
}

func createOrOpen(path, descriptor, sid string, root bool) (windows.Handle, error) {
	sd, err := windows.SecurityDescriptorFromString(descriptor)
	if err != nil {
		return 0, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	err = windows.CreateDirectory(name, &sa)
	runtime.KeepAlive(sd)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return 0, err
	}
	h, err := openDirectory(path)
	if err != nil {
		return 0, err
	}
	if err = validateDirectory(h, sid, root); err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	return h, nil
}

// provisionAt creates only this application's two fixed directories. Existing
// objects are checked, never repaired. The caller holds the installer lock and
// has already verified its administrator and captured interactive identities.
func provisionAt(location Location) error {
	parent := filepath.Dir(location.Root)
	handles, err := pinAncestors(parent)
	if err != nil {
		return err
	}
	defer func() { closeHandles(handles) }()
	for _, handle := range handles {
		if err = validateAncestor(handle); err != nil {
			return err
		}
	}
	anchor, err := pinExistingAnchor(parent)
	if err != nil {
		return err
	}
	handles = append(handles, anchor)
	if err = checkPinnedShapes(handles); err != nil {
		return err
	}
	root, err := createOrOpen(location.Root, rootDescriptor(), location.SID, true)
	if err != nil {
		return fmt.Errorf("protected application profile parent: %w", err)
	}
	handles = append(handles, root)
	user, err := createOrOpen(location.UserDirectory, userDescriptor(location.SID), location.SID, false)
	if err != nil {
		return fmt.Errorf("private desktop user directory: %w", err)
	}
	handles = append(handles, user)
	return nil
}

func Provision(sid string) error {
	location, err := LocationForSID(sid)
	if err != nil {
		return err
	}
	return provisionAt(location)
}

// OpenForToken verifies and pins the installer-created namespace until release.
// It never creates a directory or changes an existing security descriptor.
func OpenForToken(token windows.Token) (Location, func(), error) {
	location, err := LocationForToken(token)
	if err != nil {
		return Location{}, nil, err
	}
	handles, err := pinAncestors(location.UserDirectory)
	if err != nil {
		return Location{}, nil, err
	}
	fail := func(err error) (Location, func(), error) { closeHandles(handles); return Location{}, nil, err }
	// Every ancestor has a verified next component pinned beneath it, including
	// the existing user directory. Recheck after the full chain is established.
	if err = checkPinnedShapes(handles); err != nil {
		return fail(err)
	}
	for _, handle := range handles[:len(handles)-2] {
		if err = validateAncestor(handle); err != nil {
			return fail(err)
		}
	}
	if err = validateDirectory(handles[len(handles)-2], location.SID, true); err != nil {
		return fail(err)
	}
	if err = validateDirectory(handles[len(handles)-1], location.SID, false); err != nil {
		return fail(err)
	}
	return location, func() { closeHandles(handles) }, nil
}
