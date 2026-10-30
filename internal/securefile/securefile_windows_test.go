//go:build windows

package securefile

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func tree(t *testing.T) string {
	t.Helper()
	// Bootstrap ONLY a newly allocated test directory, with a private DACL at
	// creation. Public APIs deliberately require an already private parent.
	parent := os.Getenv("SECUREFILE_TEST_ROOT")
	if parent == "" {
		t.Fatal("SECUREFILE_TEST_ROOT required")
	}
	p, e := os.MkdirTemp(parent, "case-")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(p); e != nil {
		t.Fatal(e)
	}
	u, e := currentSID()
	if e != nil {
		t.Fatal(e)
	}
	if e = makeDir(p, u); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(p) })
	return p
}
func TestPrivateStorage(t *testing.T) {
	root := tree(t)
	dir := filepath.Join(root, "private")
	if e := PrivateDir(dir); e != nil {
		t.Fatal(e)
	}
	if e := PrivateDir(dir); e != nil {
		t.Fatal(e)
	}
	if e := CheckPrivate(dir, true); e != nil {
		t.Fatal(e)
	}
	f := filepath.Join(dir, "config")
	if e := os.WriteFile(f, []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := CheckPrivate(f, false); e == nil {
		t.Fatal("inherited file ACL accepted")
	}
	if e := ProtectFile(f); e != nil {
		t.Fatal(e)
	}
	if e := CheckPrivate(f, false); e != nil {
		t.Fatal(e)
	}
	if e := CheckPrivate(f, true); e == nil {
		t.Fatal("file accepted as directory")
	}
	b, e := os.ReadFile(f)
	if e != nil || string(b) != "fixture" {
		t.Fatal("data altered")
	}
}
func setTestSD(t *testing.T, path, s string) {
	t.Helper()
	p, e := syscall.UTF16PtrFromString(s)
	if e != nil {
		t.Fatal(e)
	}
	var sd uintptr
	ok, _, e := convertSD.Call(uintptr(unsafe.Pointer(p)), 1, uintptr(unsafe.Pointer(&sd)), 0)
	if e = winerr("test descriptor", ok, e); e != nil {
		t.Fatal(e)
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	var present, def int32
	var dacl uintptr
	ok, _, e = getDACL.Call(sd, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&def)))
	if e = winerr("test dacl", ok, e); e != nil {
		t.Fatal(e)
	}
	h, e := open(path, writeDAC|readControl)
	if e != nil {
		t.Fatal(e)
	}
	defer syscall.CloseHandle(h)
	code, _, _ := setInfo.Call(uintptr(h), 1, 0x80000004, 0, 0, dacl, 0)
	if code != 0 {
		t.Fatal(syscall.Errno(code))
	}
}
func TestUnsafeParentAndACL(t *testing.T) {
	root := tree(t)
	u, e := currentSID()
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(root, "public")
	if e := PrivateDir(dir); e != nil {
		t.Fatal(e)
	}
	f := filepath.Join(dir, "secret")
	if e := os.WriteFile(f, nil, 0600); e != nil {
		t.Fatal(e)
	}
	if e := ProtectFile(f); e != nil {
		t.Fatal(e)
	}
	setTestSD(t, dir, "D:P(A;OICI;FA;;;"+u+")(A;OICI;GR;;;WD)")
	if e := CheckPrivate(dir, true); e == nil {
		t.Fatal("Everyone access accepted")
	}
	if e := CheckPrivate(f, false); e == nil {
		t.Fatal("unsafe parent accepted")
	}
	if e := PrivateDir(filepath.Join(dir, "child")); e == nil {
		t.Fatal("created in public parent")
	}
	if _, e := Lock(filepath.Join(dir, "lock"), 0); e == nil {
		t.Fatal("locked in public parent")
	}
}
func TestHardlinkAndReparse(t *testing.T) {
	root := tree(t)
	dir := filepath.Join(root, "private")
	if e := PrivateDir(dir); e != nil {
		t.Fatal(e)
	}
	f := filepath.Join(dir, "f")
	if e := os.WriteFile(f, nil, 0600); e != nil {
		t.Fatal(e)
	}
	if e := ProtectFile(f); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(f, filepath.Join(dir, "other")); e != nil {
		t.Fatal(e)
	}
	if e := ProtectFile(f); e == nil {
		t.Fatal("hardlink protected")
	}
	if e := CheckPrivate(f, false); e == nil {
		t.Fatal("hardlink accepted")
	}
	if e := os.Symlink(dir, filepath.Join(root, "link")); e != nil {
		t.Log("symlink creation unavailable; reparse case not executed")
		return
	}
	if e := CheckPrivate(filepath.Join(root, "link"), true); e == nil {
		t.Fatal("reparse accepted")
	}
	if e := PrivateDir(filepath.Join(root, "link", "child")); e == nil {
		t.Fatal("reparse ancestor accepted")
	}
}
func TestInvalidPaths(t *testing.T) {
	for _, p := range []string{"relative", `C:\x\..\y`, `C:\x\file:stream`, `\\server\share\file`, `\\?\C:\file`, `C:\x\file.`, `C:\x\NUL`, `C:\x\COM1.txt`} {
		if _, e := cleanPath(p); e == nil {
			t.Fatal("accepted", p)
		}
	}
	if _, e := Lock(`C:\x\lock`, -time.Second); e == nil {
		t.Fatal("negative timeout")
	}
}
func TestLockHelper(t *testing.T) {
	path := os.Getenv("SECUREFILE_LOCK_CHILD")
	if path == "" {
		return
	}
	release, e := Lock(path, 30*time.Millisecond)
	if release != nil {
		release()
		t.Fatal("cross-process exclusion failed")
	}
	if e == nil || !strings.Contains(e.Error(), "timeout") {
		t.Fatal("expected timeout", e)
	}
}
func TestLock(t *testing.T) {
	root := tree(t)
	path := filepath.Join(root, "lock")
	release, e := Lock(path, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	if e := CheckPrivate(path, false); e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	r, e := Lock(path, 30*time.Millisecond)
	if r != nil {
		r()
	}
	if e == nil || time.Since(start) < 20*time.Millisecond {
		t.Fatal("missing exclusion timeout")
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(exe, "-test.run=^TestLockHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "SECUREFILE_LOCK_CHILD="+path)
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("child: %v %s", e, b)
	}
	release()
	release()
	again, e := Lock(path, 0)
	if e != nil {
		t.Fatal(e)
	}
	again()
	if _, e := os.Stat(path); errors.Is(e, os.ErrNotExist) {
		t.Fatal("lock file removed")
	}
}

func TestConfigRootReadOnlyPreflight(t *testing.T) {
	for _, local := range []bool{false, true} {
		profile, path, e := configLocation(local)
		if e != nil {
			t.Fatal(e)
		}
		if !strings.HasPrefix(strings.ToLower(path), strings.ToLower(profile)+`\`) {
			t.Fatal("outside profile")
		}
		// Inspect only; do not create or modify NetLaunch in actual AppData.
		h, e := open(filepath.Dir(path), readControl)
		if e != nil {
			t.Fatal(e)
		}
		user, e := currentSID()
		if e != nil {
			syscall.CloseHandle(h)
			t.Fatal(e)
		}
		e = safeParent(h, user)
		if e == nil {
			e = writableParent(h)
		}
		syscall.CloseHandle(h)
		if e != nil {
			t.Log("actual AppData preflight rejected conservatively:", e)
		}
	}
	root := tree(t)
	user, e := currentSID()
	if e != nil {
		t.Fatal(e)
	}
	h, e := open(root, readControl)
	if e != nil {
		t.Fatal(e)
	}
	defer syscall.CloseHandle(h)
	if e = safeParent(h, user); e != nil {
		t.Fatal(e)
	}
	if e = writableParent(h); e != nil {
		t.Fatal(e)
	}
	setTestSD(t, root, "D:P(A;OICI;FA;;;"+user+")(A;OICI;GW;;;WD)")
	if e = safeParent(h, user); e == nil {
		t.Fatal("public writer accepted")
	}
}

func TestJunctionRejected(t *testing.T) {
	root := tree(t)
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "junction")
	if e := PrivateDir(target); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(link, 0700); e != nil {
		t.Fatal(e)
	}
	defer os.Remove(link)
	p, e := syscall.UTF16PtrFromString(link)
	if e != nil {
		t.Fatal(e)
	}
	h, e := syscall.CreateFile(p, syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		t.Fatal(e)
	}
	substitute := syscall.StringToUTF16(`\??\` + target)
	printName := syscall.StringToUTF16(target)
	data := make([]byte, 16+2*(len(substitute)+len(printName)))
	binary.LittleEndian.PutUint32(data, 0xa0000003)
	binary.LittleEndian.PutUint16(data[4:], uint16(len(data)-8))
	binary.LittleEndian.PutUint16(data[10:], uint16(2*(len(substitute)-1)))
	binary.LittleEndian.PutUint16(data[12:], uint16(2*len(substitute)))
	binary.LittleEndian.PutUint16(data[14:], uint16(2*(len(printName)-1)))
	for i, v := range append(substitute, printName...) {
		binary.LittleEndian.PutUint16(data[16+i*2:], v)
	}
	var returned uint32
	e = syscall.DeviceIoControl(h, 0x900a4, &data[0], uint32(len(data)), nil, 0, &returned, nil)
	syscall.CloseHandle(h)
	if e != nil {
		t.Fatal(e)
	}
	if e = CheckPrivate(link, true); e == nil {
		t.Fatal("junction accepted")
	}
	if e = PrivateDir(filepath.Join(link, "child")); e == nil {
		t.Fatal("junction ancestor accepted")
	}
	if _, e = os.Stat(filepath.Join(target, "child")); !os.IsNotExist(e) {
		t.Fatal("target modified")
	}
}

func TestProfileRootNativeReadOnly(t *testing.T) {
	profile, e := profileLocation()
	if e != nil {
		t.Fatal(e)
	}
	pins, _, e := rootParents(profile, filepath.Join(profile, ".netlaunch"))
	if e != nil {
		t.Fatal(e)
	}
	closeAll(pins)
	// Intentionally do not call PrivateProfileRoot or touch the real target.
}
func TestProfileRootCreateInTestTree(t *testing.T) {
	profile := tree(t)
	path := filepath.Join(profile, ".netlaunch")
	got, e := privateRoot(profile, path)
	if e != nil || got != path {
		t.Fatal("bootstrap", e)
	}
	if e = CheckPrivate(path, true); e != nil {
		t.Fatal(e)
	}
	if _, e = privateRoot(profile, path); e != nil {
		t.Fatal("existing root", e)
	}
	if _, e = privateRoot(profile, filepath.Join(filepath.Dir(profile), "outside")); e == nil {
		t.Fatal("outside profile accepted")
	}
	user, e := currentSID()
	if e != nil {
		t.Fatal(e)
	}
	setTestSD(t, path, "D:P(A;OICI;FA;;;"+user+")(A;OICI;GR;;;WD)")
	if _, e = privateRoot(profile, path); e == nil {
		t.Fatal("existing unsafe root accepted or repaired")
	}
	if e = CheckPrivate(path, true); e == nil {
		t.Fatal("unsafe ACL silently repaired")
	}
	setTestSD(t, profile, "D:P(A;OICI;FA;;;"+user+")(A;OICI;GW;;;WD)")
	if _, e = privateRoot(profile, filepath.Join(profile, "other")); e == nil {
		t.Fatal("unsafe profile accepted")
	}
}
