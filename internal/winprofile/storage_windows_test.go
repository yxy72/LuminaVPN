//go:build windows

package winprofile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func userSID(t *testing.T) string {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid.String()
}

func fixture(t *testing.T) string {
	t.Helper()
	// These tests create only new task-owned objects and never alter the real
	// ProgramData namespace, user home, UAC or an existing directory's ACL.
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("installer-owned directory creation requires an administrator fixture")
	}
	parent := os.Getenv("SECUREFILE_TEST_ROOT")
	if parent == "" || !filepath.IsAbs(parent) {
		t.Fatal("absolute SECUREFILE_TEST_ROOT required")
	}
	path, err := os.MkdirTemp(parent, "profile-store-")
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(parent, path)
	if err != nil || rel == "." || rel == ".." || strings.ContainsAny(rel, `\/`) {
		t.Fatal("fixture escaped its allocated parent")
	}
	t.Cleanup(func() { os.RemoveAll(path) })
	return path
}

func TestNativeProfilePathUsesTokenAndKnownFolder(t *testing.T) {
	t.Setenv("PROGRAMDATA", `Z:\untrusted`)
	t.Setenv("USERPROFILE", `Z:\untrusted-user`)
	location, err := LocationForToken(windows.GetCurrentProcessToken())
	if err != nil {
		t.Fatal(err)
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, "LuminaVPN-Users", userSID(t), ".netlaunch")
	if location.Profile != want || location.SID != userSID(t) {
		t.Fatal("profile escaped the fixed native per-user namespace")
	}
	for _, sid := range []string{"", "S-1-1-0", "S-1-5-18", "S-1-5-32-544", "S-1-3-0", `..\other`, "S-1-5-21-1-2-3-1001\\escape"} {
		if _, err := locationAt(base, sid); err == nil {
			t.Fatalf("non-user/path SID accepted: %q", sid)
		}
	}
}

func TestInstallerParentsArePrivateAndPinned(t *testing.T) {
	base, sid := fixture(t), userSID(t)
	location, err := locationAt(base, sid)
	if err != nil {
		t.Fatal(err)
	}
	root, err := createOrOpen(location.Root, rootDescriptor(), sid, true)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(root)
	user, err := createOrOpen(location.UserDirectory, userDescriptor(sid), sid, false)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(user)
	if err := validateDirectory(user, "S-1-5-21-101-102-103-1001", false); err == nil {
		t.Fatal("one user's directory accepted for a different user")
	}
	if err := os.Rename(location.Root, location.Root+"-replacement"); err == nil {
		t.Fatal("an open namespace was replaceable despite the held no-delete handle")
	}
	if err := os.Rename(location.UserDirectory, location.UserDirectory+"-replacement"); err == nil {
		t.Fatal("an open private parent was replaceable")
	}
	if _, err := os.Stat(location.Profile); !os.IsNotExist(err) {
		t.Fatal("installer created or modified user configuration")
	}
}

func TestUnsafeExistingParentIsNotRepaired(t *testing.T) {
	base, sid := fixture(t), userSID(t)
	path := filepath.Join(base, "unsafe")
	// Create it with the wrong ACL from the start, then ensure the installer
	// rejects rather than converting an untrusted object into an authority.
	_, err := createOrOpen(path, "O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)", sid, true)
	if err == nil {
		t.Fatal("unsafe fixture unexpectedly matched the installer ACL")
	}
	before, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	beforeText := before.String()
	if _, err = createOrOpen(path, rootDescriptor(), sid, true); err == nil {
		t.Fatal("existing unsafe parent was accepted")
	}
	after, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || after.String() != beforeText {
		t.Fatal("existing parent security was repaired or changed")
	}
	h, err := openDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if validateAncestor(h) == nil {
		t.Fatal("replaceable ancestor was accepted")
	}
}

func TestRedirectedParentIsRejected(t *testing.T) {
	base, sid := fixture(t), userSID(t)
	target, link := filepath.Join(base, "target"), filepath.Join(base, "link")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlink creation unavailable:", err)
	}
	if _, err := createOrOpen(link, rootDescriptor(), sid, true); err == nil {
		t.Fatal("redirected existing profile namespace was accepted")
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatal("redirected target was modified")
	}
}

func TestDirectoryHandleMustMatchFinalNativePath(t *testing.T) {
	base := fixture(t)
	target, link := filepath.Join(base, "real"), filepath.Join(base, "redirected-parent")
	if err := os.MkdirAll(filepath.Join(target, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlink creation unavailable:", err)
	}
	// The final component is an ordinary directory; only its parent redirects.
	// A final-component reparse check by itself would accept the wrong object.
	if h, err := openDirectory(filepath.Join(link, "child")); err == nil {
		windows.CloseHandle(h)
		t.Fatal("a directory reached through a redirected parent was accepted")
	}
	h, err := openDirectory(filepath.Join(target, "child"))
	if err != nil {
		t.Fatal("the actual native path was rejected:", err)
	}
	windows.CloseHandle(h)
}

func TestExistingNamespaceAnchorSelection(t *testing.T) {
	for _, name := range []string{"missing", "Microsoft fallback", "unsafe setup refuses fallback", "prefer existing setup"} {
		t.Run(name, func(t *testing.T) {
			base, sid := fixture(t), userSID(t)
			microsoft, setup := filepath.Join(base, "Microsoft"), filepath.Join(base, "LuminaVPN-Setup")
			if name != "missing" {
				h, err := createOrOpen(microsoft, rootDescriptor(), sid, true)
				if err != nil {
					t.Fatal(err)
				}
				windows.CloseHandle(h)
			}
			if name == "unsafe setup refuses fallback" {
				if h, err := createOrOpen(setup, "O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)", sid, true); err == nil {
					windows.CloseHandle(h)
					t.Fatal("unsafe fixture was accepted")
				}
			} else if name == "prefer existing setup" {
				h, err := createOrOpen(setup, rootDescriptor(), sid, true)
				if err != nil {
					t.Fatal(err)
				}
				windows.CloseHandle(h)
			}
			h, err := pinExistingAnchor(base)
			if name == "missing" || name == "unsafe setup refuses fallback" {
				if err == nil {
					windows.CloseHandle(h)
					t.Fatal("missing or unsafe first anchor was bypassed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(h)
			pinned := microsoft
			if name == "prefer existing setup" {
				pinned = setup
				if err := os.Rename(microsoft, microsoft+"-not-pinned"); err != nil {
					t.Fatal("fallback was pinned instead of existing setup:", err)
				}
			}
			if err := os.Rename(pinned, pinned+"-replacement"); err == nil {
				t.Fatal("selected existing anchor was not held against replacement")
			}
		})
	}
}
