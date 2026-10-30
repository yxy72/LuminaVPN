//go:build windows

// Package securefile provides fail-closed Windows private storage primitives.
package securefile

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	adv        = syscall.NewLazyDLL("advapi32.dll")
	kern       = syscall.NewLazyDLL("kernel32.dll")
	convertSD  = adv.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	getInfo    = adv.NewProc("GetSecurityInfo")
	setInfo    = adv.NewProc("SetSecurityInfo")
	getDACL    = adv.NewProc("GetSecurityDescriptorDacl")
	getControl = adv.NewProc("GetSecurityDescriptorControl")
	getACE     = adv.NewProc("GetAce")
	lockEx     = kern.NewProc("LockFileEx")
	unlockEx   = kern.NewProc("UnlockFileEx")
	createDir  = kern.NewProc("CreateDirectoryW")
)

const (
	readControl   = 0x20000
	writeDAC      = 0x40000
	fullControl   = 0x1f01ff
	protectedDACL = 0x1000
)

func currentSID() (string, error) {
	p, e := syscall.GetCurrentProcess()
	if e != nil {
		return "", e
	}
	var token syscall.Token
	if e = syscall.OpenProcessToken(p, syscall.TOKEN_QUERY, &token); e != nil {
		return "", e
	}
	defer token.Close()
	u, e := token.GetTokenUser()
	if e != nil {
		return "", e
	}
	return u.User.Sid.String()
}
func approved(s string, user string) bool { return s == user || s == "S-1-5-18" || s == "S-1-5-32-544" }
func winerr(name string, ok uintptr, e error) error {
	if ok != 0 {
		return nil
	}
	if e == syscall.Errno(0) {
		e = syscall.EINVAL
	}
	return fmt.Errorf("securefile: %s: %w", name, e)
}
func descriptor(user string, dir bool) (uintptr, error) {
	flags := ""
	if dir {
		flags = "OICI"
	}
	s := "O:" + user + "D:P(A;" + flags + ";FA;;;" + user + ")(A;" + flags + ";FA;;;SY)(A;" + flags + ";FA;;;BA)"
	p, e := syscall.UTF16PtrFromString(s)
	if e != nil {
		return 0, e
	}
	var sd uintptr
	ok, _, e := convertSD.Call(uintptr(unsafe.Pointer(p)), 1, uintptr(unsafe.Pointer(&sd)), 0)
	return sd, winerr("convert descriptor", ok, e)
}
func closeAll(h []syscall.Handle) {
	for i := len(h) - 1; i >= 0; i-- {
		syscall.CloseHandle(h[i])
	}
}

// cleanPath deliberately rejects UNC/device paths, streams, relative paths,
// dot components, trailing dots/spaces and DOS aliases rather than normalizing.
func cleanPath(path string) (string, error) {
	p := strings.ReplaceAll(path, "/", `\`)
	if len(p) < 4 || p[1] != ':' || p[2] != '\\' || !((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) {
		return "", errors.New("securefile: local absolute path required")
	}
	for _, part := range strings.Split(p[3:], `\`) {
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if part == "" || part == "." || part == ".." || strings.TrimRight(part, " .") != part || strings.ContainsAny(part, ":\x00*?<>|\"") || base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || (len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9') {
			return "", errors.New("securefile: unsafe path component")
		}
	}
	return p, nil
}
func open(path string, access uint32) (syscall.Handle, error) {
	p, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return 0, e
	}
	return syscall.CreateFile(p, access, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}
func shape(h syscall.Handle, dir bool) error {
	return shapeLinks(h, dir, false)
}
func shapeLinks(h syscall.Handle, dir, allowUnlinked bool) error {
	var i syscall.ByHandleFileInformation
	if e := syscall.GetFileInformationByHandle(h, &i); e != nil {
		return e
	}
	if i.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("securefile: reparse point rejected")
	}
	if (i.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0) != dir {
		return errors.New("securefile: wrong object type")
	}
	if !dir && i.NumberOfLinks != 1 && !(allowUnlinked && i.NumberOfLinks == 0) {
		return errors.New("securefile: hard-linked file rejected")
	}
	return nil
}

// pinParent keeps every ancestor open without FILE_SHARE_DELETE while operating.
// The immediate parent is the private storage trust boundary: it must itself
// have a protected private DACL and an approved owner. No automatic repair of
// a public parent is attempted. Ancestor reparse points are rejected.
func pinParent(path, user string) ([]syscall.Handle, error) {
	parent := filepath.Dir(path)
	var handles []syscall.Handle
	fail := func(e error) ([]syscall.Handle, error) { closeAll(handles); return nil, e }
	root := path[:3]
	h, e := open(root, readControl)
	if e != nil {
		return nil, e
	}
	handles = append(handles, h)
	if e = shape(h, true); e != nil {
		return fail(e)
	}
	here := root
	for _, part := range strings.Split(strings.TrimPrefix(parent, root), `\`) {
		if part == "" {
			continue
		}
		here = filepath.Join(here, part)
		h, e = open(here, readControl)
		if e != nil {
			return fail(e)
		}
		handles = append(handles, h)
		if e = shape(h, true); e != nil {
			return fail(e)
		}
	}
	if e = checkACL(handles[len(handles)-1], user); e != nil {
		return fail(fmt.Errorf("securefile: unsafe parent: %w", e))
	}
	return handles, nil
}
func ownerAndDACL(h syscall.Handle) (owner *syscall.SID, dacl unsafe.Pointer, sd uintptr, err error) {
	code, _, _ := getInfo.Call(uintptr(h), 1, 5, uintptr(unsafe.Pointer(&owner)), 0, uintptr(unsafe.Pointer(&dacl)), 0, uintptr(unsafe.Pointer(&sd)))
	if code != 0 {
		err = syscall.Errno(code)
	}
	return
}
func checkOwner(h syscall.Handle, user string) error {
	owner, _, sd, e := ownerAndDACL(h)
	if e != nil {
		return e
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	if owner == nil {
		return errors.New("securefile: missing owner")
	}
	s, e := owner.String()
	if e != nil {
		return e
	}
	if !approved(s, user) {
		return errors.New("securefile: unapproved owner")
	}
	return nil
}
func checkACL(h syscall.Handle, user string) error {
	owner, dacl, sd, e := ownerAndDACL(h)
	if e != nil {
		return e
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	if owner == nil || dacl == nil {
		return errors.New("securefile: missing owner or NULL DACL")
	}
	s, e := owner.String()
	if e != nil {
		return e
	}
	if !approved(s, user) {
		return errors.New("securefile: unapproved owner")
	}
	var control uint16
	var revision uint32
	ok, _, e := getControl.Call(sd, uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&revision)))
	if e = winerr("descriptor control", ok, e); e != nil {
		return e
	}
	if control&protectedDACL == 0 {
		return errors.New("securefile: inherited DACL rejected")
	}
	// ACL header is 8 bytes; ACE count is the uint16 at offset 4.
	count := *(*uint16)(unsafe.Add(dacl, 4))
	if count == 0 {
		return errors.New("securefile: empty DACL")
	}
	userFull := false
	for n := uint16(0); n < count; n++ {
		var ace unsafe.Pointer
		ok, _, e = getACE.Call(uintptr(dacl), uintptr(n), uintptr(unsafe.Pointer(&ace)))
		if e = winerr("GetAce", ok, e); e != nil {
			return e
		}
		header := unsafe.Slice((*byte)(ace), 8)
		// Only ordinary ACCESS_ALLOWED_ACE entries are accepted. Deny, callback,
		// object, inherited and inherit-only ACEs fail closed.
		if header[0] != 0 || header[1]&^byte(3) != 0 || *(*uint16)(unsafe.Add(ace, 2)) < 16 {
			return errors.New("securefile: unsupported ACE")
		}
		sid := (*syscall.SID)(unsafe.Add(ace, 8))
		s, e = sid.String()
		if e != nil {
			return e
		}
		if !approved(s, user) {
			return errors.New("securefile: unapproved ACL trustee")
		}
		mask := *(*uint32)(unsafe.Add(ace, 4))
		if mask & ^uint32(fullControl) != 0 {
			return errors.New("securefile: unsupported access mask")
		}
		if s == user && mask&fullControl == fullControl {
			userFull = true
		}
	}
	if !userFull {
		return errors.New("securefile: current user lacks explicit full control")
	}
	return nil
}
func protect(h syscall.Handle, user string, dir bool) error {
	sd, e := descriptor(user, dir)
	if e != nil {
		return e
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	var present, defaulted int32
	var dacl unsafe.Pointer
	ok, _, e := getDACL.Call(sd, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted)))
	if e = winerr("descriptor DACL", ok, e); e != nil {
		return e
	}
	if present == 0 || dacl == nil {
		return errors.New("securefile: invalid generated DACL")
	}
	code, _, _ := setInfo.Call(uintptr(h), 1, 0x80000004, 0, 0, uintptr(dacl), 0)
	runtime.KeepAlive(sd)
	if code != 0 {
		return syscall.Errno(code)
	}
	return checkACL(h, user)
}
func makeDir(path, user string) error {
	sd, e := descriptor(user, true)
	if e != nil {
		return e
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	sa := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: sd}
	p, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	ok, _, e := createDir.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&sa)))
	return winerr("CreateDirectory", ok, e)
}

// PrivateDir creates one directory with a protected DACL atomically, or verifies
// an existing one. Its parent must already be private. It never chmods parents.
func PrivateDir(path string) error {
	user, e := currentSID()
	if e != nil {
		return e
	}
	return privateDirAs(path, user)
}
func privateDirAs(path string, user string) error {
	path, e := cleanPath(path)
	if e != nil {
		return e
	}
	pins, e := pinParent(path, user)
	if e != nil {
		return e
	}
	defer closeAll(pins)
	e = makeDir(path, user)
	if e != nil && !errors.Is(e, syscall.ERROR_ALREADY_EXISTS) {
		return e
	}
	h, e := open(path, readControl)
	if e != nil {
		return e
	}
	defer syscall.CloseHandle(h)
	if e = shape(h, true); e != nil {
		return e
	}
	return checkACL(h, user)
}

// CheckPrivate validates type, owner and a protected DACL. It rejects reparse
// ancestors, hard-linked files and a non-private immediate parent.
func CheckPrivate(path string, isDir bool) error {
	user, e := currentSID()
	if e != nil {
		return e
	}
	return checkPrivateAs(path, isDir, user)
}
func checkPrivateAs(path string, isDir bool, user string) error {
	path, e := cleanPath(path)
	if e != nil {
		return e
	}
	pins, e := pinParent(path, user)
	if e != nil {
		return e
	}
	defer closeAll(pins)
	h, e := open(path, readControl)
	if e != nil {
		return e
	}
	defer syscall.CloseHandle(h)
	if e = shape(h, isDir); e != nil {
		return e
	}
	return checkACL(h, user)
}

// ProtectFile restricts an existing, single-link regular file owned by an
// approved principal. The parent must already be private. This cannot undo
// disclosure that occurred before protection or revoke previously open handles.
func ProtectFile(path string) error {
	path, e := cleanPath(path)
	if e != nil {
		return e
	}
	user, e := currentSID()
	if e != nil {
		return e
	}
	pins, e := pinParent(path, user)
	if e != nil {
		return e
	}
	defer closeAll(pins)
	h, e := open(path, readControl|writeDAC)
	if e != nil {
		return e
	}
	defer syscall.CloseHandle(h)
	if e = shape(h, false); e != nil {
		return e
	}
	if e = checkOwner(h, user); e != nil {
		return e
	}
	return protect(h, user, false)
}

// Lock creates/opens a private lock file and exclusively locks byte zero using
// LockFileEx. It polls without blocking the thread indefinitely. The returned
// release is idempotent; the file is retained, avoiding inode replacement races.
func Lock(path string, timeout time.Duration) (func(), error) {
	user, e := currentSID()
	if e != nil {
		return nil, e
	}
	return lockAs(path, timeout, user)
}
func lockAs(path string, timeout time.Duration, user string) (func(), error) {
	if timeout < 0 {
		return nil, errors.New("securefile: negative timeout")
	}
	path, e := cleanPath(path)
	if e != nil {
		return nil, e
	}
	pins, e := pinParent(path, user)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (func(), error) { closeAll(pins); return nil, e }
	sd, e := descriptor(user, false)
	if e != nil {
		return fail(e)
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	sa := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: sd}
	p, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return fail(e)
	}
	h, e := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE|readControl, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, &sa, syscall.OPEN_ALWAYS, syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return fail(e)
	}
	pins = append(pins, h)
	if e = shape(h, false); e != nil {
		return fail(e)
	}
	if e = checkACL(h, user); e != nil {
		return fail(e)
	}
	until := time.Now().Add(timeout)
	var ov syscall.Overlapped
	for {
		ok, _, e := lockEx.Call(uintptr(h), 3, 0, 1, 0, uintptr(unsafe.Pointer(&ov)))
		if ok != 0 {
			break
		}
		if e != syscall.Errno(33) {
			return fail(winerr("LockFileEx", ok, e))
		}
		remain := time.Until(until)
		if remain <= 0 {
			return fail(fmt.Errorf("securefile: lock timeout: %w", e))
		}
		if remain > 10*time.Millisecond {
			remain = 10 * time.Millisecond
		}
		time.Sleep(remain)
	}
	var once sync.Once
	return func() {
		once.Do(func() { unlockEx.Call(uintptr(h), 0, 1, 0, uintptr(unsafe.Pointer(&ov))); closeAll(pins) })
	}, nil
}
