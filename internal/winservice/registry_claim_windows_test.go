//go:build windows

package winservice

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"runtime"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestRegistryClaimOwnLeafNative(t *testing.T) {
	// This test creates only its random HKCU fixture. It never calls the fixed
	// production claim or opens HKLM for mutation, and never elevates itself.
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("protected machine-style descriptor requires an existing administrator token")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	path := `Software\LuminaRegistryClaimTest-` + hex.EncodeToString(random[:])
	parent, existing, err := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS|registry.WOW64_64KEY)
	if err != nil || existing {
		t.Fatalf("create isolated fixture: %v existing=%v", err, existing)
	}
	t.Cleanup(func() {
		for _, name := range []string{"fresh", "unsafe", "link", "target"} {
			key, err := openRegistryLinkAccess(parent, name, registry.WOW64_64KEY, registry.ALL_ACCESS)
			if errors.Is(err, registry.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Error(err)
				continue
			}
			status, _, _ := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtDeleteKey").Call(uintptr(key))
			if status != 0 {
				t.Error(windows.NTStatus(status))
			}
			_ = key.Close()
		}
		_ = parent.Close()
		if err := registry.DeleteKey(registry.CURRENT_USER, path); err != nil {
			t.Error(err)
		}
	})
	before, err := windows.GetSecurityInfo(windows.Handle(parent), windows.SE_REGISTRY_KEY, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	parentSD := before.String()

	t.Run("new leaf and retry preserve parent and values", func(t *testing.T) {
		key, err := claimRegistryLeaf(parent, "fresh", registry.WOW64_64KEY, "")
		if err != nil {
			t.Fatal(err)
		}
		_ = key.Close()
		writer, err := openRegistryLinkAccess(parent, "fresh", registry.WOW64_64KEY, registry.ALL_ACCESS)
		if err != nil {
			t.Fatal(err)
		}
		if err = writer.SetStringValue("Fixture", "unchanged"); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		key, err = claimRegistryLeaf(parent, "fresh", registry.WOW64_64KEY, "")
		if err != nil {
			t.Fatal(err)
		}
		defer key.Close()
		value, _, err := key.GetStringValue("Fixture")
		if err != nil || value != "unchanged" {
			t.Fatalf("existing values changed: %q %v", value, err)
		}
	})
	t.Run("existing unsafe leaf is rejected without repair", func(t *testing.T) {
		key, _, err := registry.CreateKey(parent, "unsafe", registry.ALL_ACCESS|registry.WOW64_64KEY)
		if err != nil {
			t.Fatal(err)
		}
		defer key.Close()
		sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KA;;;WD)")
		if err != nil {
			t.Fatal(err)
		}
		owner, _, _ := sd.Owner()
		acl, _, _ := sd.DACL()
		if err = windows.SetSecurityInfo(windows.Handle(key), windows.SE_REGISTRY_KEY,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil); err != nil {
			t.Fatal(err)
		}
		if claimed, err := claimRegistryLeaf(parent, "unsafe", registry.WOW64_64KEY, ""); err == nil {
			claimed.Close()
			t.Fatal("unsafe existing key adopted")
		}
		if checkRegistryKey(key, "") == nil {
			t.Fatal("claim repaired an unsafe key")
		}
	})
	t.Run("existing symbolic link is never followed", func(t *testing.T) {
		target, _, err := registry.CreateKey(parent, "target", registry.ALL_ACCESS|registry.WOW64_64KEY)
		if err != nil {
			t.Fatal(err)
		}
		defer target.Close()
		if err = target.SetStringValue("Fixture", "target remains unchanged"); err != nil {
			t.Fatal(err)
		}
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			t.Fatal(err)
		}
		nativeTarget := `\Registry\User\` + user.User.Sid.String() + `\` + path + `\target`
		name, _ := windows.NewNTUnicodeString("link")
		sd, _ := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)")
		oa := windows.OBJECT_ATTRIBUTES{RootDirectory: windows.Handle(parent), ObjectName: name,
			Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_OPENLINK, SecurityDescriptor: sd}
		oa.Length = uint32(unsafe.Sizeof(oa))
		var handle windows.Handle
		var disposition uint32
		status, _, _ := ntCreateRegistryKey.Call(uintptr(unsafe.Pointer(&handle)), registry.ALL_ACCESS|registry.WOW64_64KEY,
			uintptr(unsafe.Pointer(&oa)), 0, 0, 2, uintptr(unsafe.Pointer(&disposition)))
		runtime.KeepAlive(name)
		runtime.KeepAlive(sd)
		if status != 0 {
			t.Fatal(windows.NTStatus(status))
		}
		defer registry.Key(handle).Close()
		valueName, _ := windows.UTF16PtrFromString("SymbolicLinkValue")
		value, _ := windows.UTF16FromString(nativeTarget)
		code, _, _ := windows.NewLazySystemDLL("advapi32.dll").NewProc("RegSetValueExW").Call(uintptr(handle),
			uintptr(unsafe.Pointer(valueName)), 0, registry.LINK, uintptr(unsafe.Pointer(&value[0])), uintptr((len(value)-1)*2))
		if code != 0 {
			t.Fatal(syscall.Errno(code))
		}
		if claimed, err := claimRegistryLeaf(parent, "link", registry.WOW64_64KEY, ""); err == nil {
			claimed.Close()
			t.Fatal("registry symbolic link accepted")
		}
		text, _, err := target.GetStringValue("Fixture")
		if err != nil || text != "target remains unchanged" {
			t.Fatal("link target changed", err)
		}
	})
	after, err := windows.GetSecurityInfo(windows.Handle(parent), windows.SE_REGISTRY_KEY, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || after.String() != parentSD {
		t.Fatal("claim modified parent security", err)
	}
}
