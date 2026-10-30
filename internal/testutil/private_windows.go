//go:build windows

// Package testutil creates private scratch fixtures; it never repairs existing
// user directories or weakens production storage checks for tests.
package testutil

import (
	"golang.org/x/sys/windows"
	"path/filepath"
	"testing"
	"unsafe"
)

func descriptor(t *testing.T, public bool) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		t.Fatal(e)
	}
	sid := u.User.Sid.String()
	s := "O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	if public {
		s += "(A;;GR;;;WD)"
	}
	sd, e := windows.SecurityDescriptorFromString(s)
	if e != nil {
		t.Fatal(e)
	}
	return sd
}

func PrivateTempDir(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	sd := descriptor(t, false)
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	for _, part := range []string{"private", "case"} {
		base = filepath.Join(base, part)
		name, e := windows.UTF16PtrFromString(base)
		if e != nil {
			t.Fatal(e)
		}
		if e = windows.CreateDirectory(name, &sa); e != nil {
			t.Fatal(e)
		}
	}
	return base
}

func MakePublic(t *testing.T, path string) {
	t.Helper()
	sd := descriptor(t, true)
	dacl, _, e := sd.DACL()
	if e != nil {
		t.Fatal(e)
	}
	if e = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); e != nil {
		t.Fatal(e)
	}
}
