//go:build windows

package securefile

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// ProfilePath is read-only and ignores environment-provided profile overrides.
func ProfilePath() (string, error) {
	token, e := tokenForUser()
	if e != nil {
		return "", e
	}
	defer token.Close()
	b := make([]uint16, 32768)
	n := uint32(len(b))
	ok, _, e := profileDir.Call(uintptr(token), uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&n)))
	if e = winerr("GetUserProfileDirectory", ok, e); e != nil {
		return "", e
	}
	p, e := cleanPath(syscall.UTF16ToString(b))
	if e != nil {
		return "", e
	}
	return filepath.Join(p, ".netlaunch"), nil
}

func Dir(path string) error {
	p, e := cleanPath(path)
	if e != nil {
		return e
	}
	root, e := ProfilePath()
	if e != nil {
		return e
	}
	if strings.EqualFold(p, root) {
		_, e = PrivateProfileRoot()
		return e
	}
	if strings.HasPrefix(strings.ToLower(p), strings.ToLower(root)+`\`) {
		if e = Dir(filepath.Dir(p)); e != nil {
			return e
		}
	}
	return PrivateDir(p)
}
func CheckDir(path string) error { return CheckPrivate(path, true) }

func Read(path string, limit int64, private bool) ([]byte, error) {
	user, e := currentSID()
	if e != nil {
		return nil, e
	}
	return readAs(path, limit, private, user)
}
func readAs(path string, limit int64, private bool, user string) ([]byte, error) {
	return readAsBounded(path, limit, private, user, false)
}

// ReadTail retains Read's handle identity, reparse, link and private ACL checks.
func ReadTail(path string, limit int64, private bool) ([]byte, error) {
	user, err := currentSID()
	if err != nil {
		return nil, err
	}
	return readAsBounded(path, limit, private, user, true)
}
func readAsBounded(path string, limit int64, private bool, user string, tail bool) ([]byte, error) {
	if limit < 0 || limit == math.MaxInt64 {
		return nil, errors.New("invalid read limit")
	}
	p, e := cleanPath(path)
	if e != nil {
		return nil, e
	}
	if private {
		pins, e := pinParent(p, user)
		if e != nil {
			return nil, e
		}
		defer closeAll(pins)
	}
	name, e := syscall.UTF16PtrFromString(p)
	if e != nil {
		return nil, e
	}
	// The file handle is the read authority. Sharing delete permits atomic
	// replacement by our writer while this reader retains its original snapshot.
	h, e := syscall.CreateFile(name, syscall.GENERIC_READ|readControl, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(h), p)
	defer f.Close()
	// A concurrent atomic replacement can unlink this already-open snapshot.
	// Zero links is safe for reading this handle; multiple links remain rejected.
	if e = shapeLinks(h, false, true); e != nil {
		return nil, e
	}
	if private {
		if e = checkACL(h, user); e != nil {
			return nil, e
		}
	}
	i, e := f.Stat()
	if e != nil || (!tail && i.Size() > limit) {
		return nil, errors.New("file size limit exceeded")
	}
	if tail {
		if i.Size() > limit {
			if _, e := f.Seek(i.Size()-limit, io.SeekStart); e != nil {
				return nil, e
			}
		}
		return io.ReadAll(io.LimitReader(f, limit))
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(b)) > limit {
		return nil, errors.New("file size limit exceeded")
	}
	return b, e
}

func Write(path string, value any) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	return Bytes(path, append(b, '\n'))
}

func Bytes(path string, data []byte) error {
	user, e := currentSID()
	if e != nil {
		return e
	}
	return bytesAs(path, data, user, Dir)
}
func bytesAs(path string, data []byte, user string, dir func(string) error) error {
	p, e := cleanPath(path)
	if e != nil {
		return e
	}
	if e = dir(filepath.Dir(p)); e != nil {
		return e
	}
	pins, e := pinParent(p, user)
	if e != nil {
		return e
	}
	defer closeAll(pins)
	if old, e := open(p, readControl); e == nil {
		e = shape(old, false)
		if e == nil {
			e = checkACL(old, user)
		}
		syscall.CloseHandle(old)
		if e != nil {
			return e
		}
	} else if !errors.Is(e, syscall.ERROR_FILE_NOT_FOUND) {
		return e
	}
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	tmp := filepath.Join(filepath.Dir(p), ".write-"+hex.EncodeToString(nonce))
	defer os.Remove(tmp)
	sd, e := descriptor(user, false)
	if e != nil {
		return e
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	sa := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: sd}
	name, e := syscall.UTF16PtrFromString(tmp)
	if e != nil {
		return e
	}
	h, e := syscall.CreateFile(name, syscall.GENERIC_WRITE|readControl|0x10000, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_DELETE, &sa, syscall.CREATE_NEW, syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(h), tmp)
	defer f.Close()
	if e = shape(h, false); e == nil {
		e = checkACL(h, user)
	}
	if e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	if e != nil {
		return e
	}
	target, e := syscall.UTF16FromString(p)
	if e != nil {
		return e
	}
	// FileRenameInfoEx with POSIX semantics keeps existing readers on the old
	// file while new readers immediately see the replacement. MoveFileEx can
	// leave a replaced target delete-pending while those readers remain open.
	// This prototype requires 64-bit Windows 10+; unsupported filesystems fail.
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return errors.New("private atomic replacement requires 64-bit Windows")
	}
	target = target[:len(target)-1]
	// The Win32 path conversion also consumes a NUL-terminated FileName.
	// Keep the terminator and structure tail padding outside FileNameLength;
	// otherwise some path lengths read beyond the buffer and rename elsewhere.
	info := make([]byte, 24+2*len(target))
	binary.LittleEndian.PutUint32(info, 3) // REPLACE_IF_EXISTS | POSIX_SEMANTICS
	binary.LittleEndian.PutUint32(info[16:], uint32(2*len(target)))
	for i, ch := range target {
		binary.LittleEndian.PutUint16(info[20+i*2:], ch)
	}
	ok, _, renameErr := kern.NewProc("SetFileInformationByHandle").Call(uintptr(h), 22, uintptr(unsafe.Pointer(&info[0])), uintptr(len(info)))
	if e := winerr("atomic replace", ok, renameErr); e != nil {
		return e
	}
	// Verify the same handle that was created with the private descriptor.
	return checkACL(h, user)
}

func TempDir(parent, prefix string) (string, error) {
	if strings.ContainsAny(prefix, `\/:`) {
		return "", errors.New("invalid private directory prefix")
	}
	if e := Dir(parent); e != nil {
		return "", e
	}
	user, e := currentSID()
	if e != nil {
		return "", e
	}
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		return "", e
	}
	p := filepath.Join(parent, prefix+hex.EncodeToString(nonce))
	pins, e := pinParent(p, user)
	if e != nil {
		return "", e
	}
	defer closeAll(pins)
	if e = makeDir(p, user); e != nil {
		return "", e
	}
	if e = CheckPrivate(p, true); e != nil {
		return "", e
	}
	return p, nil
}
