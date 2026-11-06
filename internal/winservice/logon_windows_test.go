//go:build windows

package winservice

import (
	"testing"
	"unsafe"
)

func TestLogonSessionPrefixMatchesDocumentedWindowsAMD64Layout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("client package targets amd64")
	}
	var value lsaLogonPrefix
	if unsafe.Sizeof(value) != 88 || unsafe.Offsetof(value.LogonID) != 4 || unsafe.Offsetof(value.User) != 16 || unsafe.Offsetof(value.LogonTime) != 80 {
		t.Fatal("SECURITY_LOGON_SESSION_DATA prefix layout mismatch")
	}
}
