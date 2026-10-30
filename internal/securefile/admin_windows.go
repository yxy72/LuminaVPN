//go:build windows

package securefile

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const administratorSID = "S-1-5-32-544"

// AdminStore uses a protected DACL with only Administrators and SYSTEM.
// A filtered UAC token therefore cannot rewrite the recovery journal, even
// when its user created the corresponding public profile.
type AdminStore struct{ Root string }

// AdminLocation is read-only and uses the native Known Folder, never an
// environment variable supplied by the process requesting elevation.
func AdminLocation() (string, error) {
	base, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if e != nil {
		return "", e
	}
	base, e = cleanPath(base)
	if e != nil {
		return "", e
	}
	return filepath.Join(base, "NetLaunch"), nil
}

func RequireAdmin() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("Windows administrator authorization is required")
	}
	sid, e := windows.StringToSid(administratorSID)
	if e != nil {
		return e
	}
	ok, e := windows.Token(0).IsMember(sid)
	if e != nil {
		return e
	}
	if !ok {
		return errors.New("an administrator token is required")
	}
	return nil
}

func OpenAdminStore() (AdminStore, error) {
	if e := RequireAdmin(); e != nil {
		return AdminStore{}, e
	}
	root, e := AdminLocation()
	if e != nil {
		return AdminStore{}, e
	}
	if e = adminRoot(root); e != nil {
		return AdminStore{}, e
	}
	return AdminStore{Root: root}, nil
}

// Only creation of siblings is permitted to untrusted principals on the
// ProgramData parent. They cannot alter its ACL or delete/replace our child.
func adminParent(h syscall.Handle) error {
	owner, dacl, sd, e := ownerAndDACL(h)
	if e != nil {
		return e
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	if owner == nil || dacl == nil {
		return errors.New("administrator parent has no owner or DACL")
	}
	sid, e := owner.String()
	if e != nil {
		return e
	}
	if !approved(sid, administratorSID) {
		return errors.New("administrator parent has an untrusted owner")
	}
	count := *(*uint16)(unsafe.Add(dacl, 4))
	for i := uint16(0); i < count; i++ {
		var ace unsafe.Pointer
		ok, _, e := getACE.Call(uintptr(dacl), uintptr(i), uintptr(unsafe.Pointer(&ace)))
		if e = winerr("admin parent GetAce", ok, e); e != nil {
			return e
		}
		header := unsafe.Slice((*byte)(ace), 8)
		if *(*uint16)(unsafe.Add(ace, 2)) < 16 || (header[0] != 0 && header[0] != 1) {
			return errors.New("unsupported administrator parent ACE")
		}
		if header[0] == 1 || header[1]&8 != 0 {
			continue
		}
		sid, e := (*syscall.SID)(unsafe.Add(ace, 8)).String()
		if e != nil {
			return e
		}
		mask := *(*uint32)(unsafe.Add(ace, 4))
		// GENERIC_ALL/WRITE, DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER.
		if !approved(sid, administratorSID) && mask&0x500d0040 != 0 {
			return errors.New("administrator parent permits external replacement")
		}
	}
	return writableParent(h)
}

func adminRoot(root string) error {
	p, e := cleanPath(root)
	if e != nil {
		return e
	}
	var pins []syscall.Handle
	defer func() { closeAll(pins) }()
	here := p[:3]
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(p), here), `\`)
	for i := -1; i < len(parts); i++ {
		if i >= 0 {
			here = filepath.Join(here, parts[i])
		}
		h, e := open(here, readControl)
		if e != nil {
			return e
		}
		pins = append(pins, h)
		if e = shape(h, true); e != nil {
			return e
		}
	}
	if e = adminParent(pins[len(pins)-1]); e != nil {
		return e
	}
	e = makeDir(p, administratorSID)
	if e != nil && !errors.Is(e, syscall.ERROR_ALREADY_EXISTS) {
		return e
	}
	h, e := open(p, readControl)
	if e != nil {
		return e
	}
	pins = append(pins, h)
	if e = shape(h, true); e != nil {
		return e
	}
	return checkACL(h, administratorSID)
}

func (s AdminStore) path(relative string) (string, error) {
	if e := RequireAdmin(); e != nil {
		return "", e
	}
	root, e := cleanPath(s.Root)
	if e != nil {
		return "", e
	}
	if filepath.IsAbs(relative) || relative == "" || relative == "." {
		return "", errors.New("administrator relative path required")
	}
	// Validate without cleaning so a traversal cannot be normalized away.
	p, e := cleanPath(root + `\` + relative)
	if e != nil {
		return "", e
	}
	if !strings.HasPrefix(strings.ToLower(p), strings.ToLower(root)+`\`) {
		return "", errors.New("path outside administrator storage")
	}
	return p, nil
}
func (s AdminStore) Dir(relative string) error {
	p, e := s.path(relative)
	if e != nil {
		return e
	}
	relativePath, e := filepath.Rel(s.Root, p)
	if e != nil {
		return e
	}
	current := s.Root
	for _, part := range strings.Split(relativePath, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		if e = privateDirAs(current, administratorSID); e != nil {
			return e
		}
	}
	return nil
}
func (s AdminStore) Check(relative string, dir bool) error {
	p, e := s.path(relative)
	if e != nil {
		return e
	}
	return checkPrivateAs(p, dir, administratorSID)
}
func (s AdminStore) Read(relative string, limit int64) ([]byte, error) {
	p, e := s.path(relative)
	if e != nil {
		return nil, e
	}
	return readAs(p, limit, true, administratorSID)
}
func (s AdminStore) Bytes(relative string, data []byte) error {
	p, e := s.path(relative)
	if e != nil {
		return e
	}
	// The immediate parent already exists and is checked without requiring
	// ProgramData itself to have the stricter private-child DACL.
	return bytesAs(p, data, administratorSID, func(dir string) error {
		h, e := open(dir, readControl)
		if e != nil {
			return e
		}
		defer syscall.CloseHandle(h)
		if e = shape(h, true); e != nil {
			return e
		}
		return checkACL(h, administratorSID)
	})
}
func (s AdminStore) Write(relative string, value any) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	return s.Bytes(relative, append(b, '\n'))
}
func (s AdminStore) Lock(relative string, timeout time.Duration) (func(), error) {
	p, e := s.path(relative)
	if e != nil {
		return nil, e
	}
	return lockAs(p, timeout, administratorSID)
}
