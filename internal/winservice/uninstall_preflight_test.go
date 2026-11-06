package winservice

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Frozen data from app-builder-lib 26.18's multiUser.nsh and
// include/installer.nsh: Software\APP_GUID owns InstallLocation, while the
// uninstall key owns the quoted EXE plus precisely one /allusers switch.
const builderFixtureID = "c84a9b46-bb2f-5cc1-9b9c-69040610df7f"
const builderFixtureRoot = `C:\Program Files\LuminaVPN`
const builderFixtureInstall = `Software\` + builderFixtureID
const builderFixtureUninstall = `Software\Microsoft\Windows\CurrentVersion\Uninstall\` + builderFixtureID

type legacyRegistryFixture struct {
	machine map[string]map[string]string
	user    map[string]bool
	unsafe  map[string]error
	reads   []string
	opened  int
	closed  int
}
type legacyRegistryFixtureKey struct {
	fixture *legacyRegistryFixture
	name    string
	values  map[string]string
}

func registryFixtureKey(view uint32, path string) string { return fmt.Sprintf("%x:%s", view, path) }
func (f *legacyRegistryFixture) OpenMachine(view uint32, path string) (legacyRegistryKey, error) {
	name := registryFixtureKey(view, path)
	if err := f.unsafe[name]; err != nil {
		return nil, err
	}
	values, ok := f.machine[name]
	if !ok {
		return nil, errLegacyRegistryMissing
	}
	f.opened++
	return &legacyRegistryFixtureKey{f, name, values}, nil
}
func (f *legacyRegistryFixture) HasCurrentUserKey(view uint32, path string) (bool, error) {
	return f.user[registryFixtureKey(view, path)], nil
}
func (f *legacyRegistryFixture) ProbeMachine(view uint32, path string) (bool, error) {
	name := registryFixtureKey(view, path)
	if err := f.unsafe[name]; err != nil {
		return false, err
	}
	_, exists := f.machine[name]
	return exists, nil
}
func (key *legacyRegistryFixtureKey) StringValue(name string) (string, error) {
	key.fixture.reads = append(key.fixture.reads, key.name+":"+name)
	value, exists := key.values[name]
	if !exists {
		return "", errLegacyRegistryValueMissing
	}
	return value, nil
}
func (key *legacyRegistryFixtureKey) Close() error { key.fixture.closed++; return nil }

func normalLegacyFixture() *legacyRegistryFixture {
	return &legacyRegistryFixture{
		machine: map[string]map[string]string{
			registryFixtureKey(0x100, builderFixtureInstall):   {"InstallLocation": builderFixtureRoot},
			registryFixtureKey(0x100, builderFixtureUninstall): {"UninstallString": `"C:\Program Files\LuminaVPN\Uninstall LuminaVPN.exe" /allusers`},
		},
		user: map[string]bool{}, unsafe: map[string]error{},
	}
}

func TestLegacyPreflightAcceptsRealBuilderMachineRegistration(t *testing.T) {
	if luminaUninstallID() != builderFixtureID {
		t.Fatal("product UUID differs from the fixed builder fixture")
	}
	// APP_64 makes the pinned NSIS template select only the 64-bit machine
	// registry view for the old uninstaller. The other view must be absent.
	f := normalLegacyFixture()
	checked := 0
	err := checkLegacyUninstall(builderFixtureRoot, f, func(path string) error {
		checked++
		if path != filepath.Join(builderFixtureRoot, "Uninstall LuminaVPN.exe") {
			t.Fatal("preflight left the fixed file")
		}
		return nil
	})
	if err != nil || checked != 1 || f.closed != f.opened {
		t.Fatalf("real x64 builder layout was rejected or handles leaked: %v", err)
	}
	if strings.Contains(strings.Join(f.reads, "\n"), builderFixtureUninstall+":InstallLocation") {
		t.Fatal("InstallLocation was read from the uninstall key")
	}
}

func TestLegacyPreflightRejects32BitMachineRegistrationsSkippedByFixedInstaller(t *testing.T) {
	for _, coexist := range []bool{false, true} {
		name := map[bool]string{false: "32-bit-only", true: "both-views"}[coexist]
		t.Run(name, func(t *testing.T) {
			f := normalLegacyFixture()
			for _, path := range []string{builderFixtureInstall, builderFixtureUninstall} {
				f.machine[registryFixtureKey(0x200, path)] = f.machine[registryFixtureKey(0x100, path)]
				if !coexist {
					delete(f.machine, registryFixtureKey(0x100, path))
				}
			}
			err := checkLegacyUninstall(builderFixtureRoot, f, func(string) error { return nil })
			if err == nil || !strings.Contains(err.Error(), "32-bit legacy machine registration") || f.closed != f.opened {
				t.Fatalf("unsupported 32-bit machine registration accepted or handles leaked: %v", err)
			}
		})
	}
}

func TestLegacyPreflightRejectsBroadenedCommandsAndPartialRegistration(t *testing.T) {
	for _, change := range []string{"no-switch", "extra-switch", "repeat-switch", "current-user-switch", "wrong-location", "missing-install", "missing-uninstall", "file-ACL"} {
		t.Run(change, func(t *testing.T) {
			f := normalLegacyFixture()
			command := f.machine[registryFixtureKey(0x100, builderFixtureUninstall)]
			switch change {
			case "no-switch":
				command["UninstallString"] = strings.TrimSuffix(command["UninstallString"], " /allusers")
			case "extra-switch":
				command["UninstallString"] += " /S"
			case "repeat-switch":
				command["UninstallString"] += " /allusers"
			case "current-user-switch":
				command["UninstallString"] = strings.ReplaceAll(command["UninstallString"], "/allusers", "/currentuser")
			case "wrong-location":
				f.machine[registryFixtureKey(0x100, builderFixtureInstall)]["InstallLocation"] = `C:\Users\Example\LuminaVPN`
			case "missing-install":
				delete(f.machine, registryFixtureKey(0x100, builderFixtureInstall))
			case "missing-uninstall":
				delete(f.machine, registryFixtureKey(0x100, builderFixtureUninstall))
			}
			err := checkLegacyUninstall(builderFixtureRoot, f, func(string) error {
				if change == "file-ACL" {
					return errors.New("untrusted file ACL")
				}
				return nil
			})
			if err == nil || f.closed != f.opened {
				t.Fatalf("unsafe/partial registration accepted or handles leaked: %v", err)
			}
		})
	}
}

func TestLegacyPreflightRejectsUserRegistrationsAndUnsafeMachineAncestors(t *testing.T) {
	for _, view := range []uint32{0x100, 0x200} {
		for _, path := range []string{builderFixtureInstall, builderFixtureUninstall, legacyUninstallPrefix + "{" + builderFixtureID + "}", legacyUninstallPrefix + "app.luminavpn.desktop"} {
			f := normalLegacyFixture()
			f.user[registryFixtureKey(view, path)] = true
			if checkLegacyUninstall(builderFixtureRoot, f, func(string) error { return nil }) == nil {
				t.Fatal("HKCU registration was treated as machine authority")
			}
		}
		f := normalLegacyFixture()
		f.unsafe[registryFixtureKey(view, builderFixtureUninstall)] = errors.New("untrusted registry ancestor")
		if checkLegacyUninstall(builderFixtureRoot, f, func(string) error { return nil }) == nil {
			t.Fatal("unsafe registry ancestor was ignored, including an absent key")
		}
	}
	f := &legacyRegistryFixture{}
	if err := checkLegacyUninstall(builderFixtureRoot, f, func(string) error { return fs.ErrNotExist }); err != nil {
		t.Fatal("clean first install was rejected", err)
	}
}

func TestRegistryDescriptorRejectsEveryUntrustedMutationRight(t *testing.T) {
	const users = "S-1-5-32-545"
	for _, right := range []uint32{2, 4, 0x20, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000} {
		if validateRegistryDescriptor("S-1-5-18", []protectedACE{{Kind: 0, SID: users, Mask: right}}, "") == nil {
			t.Fatalf("untrusted registry right %#x accepted", right)
		}
	}
	read := []protectedACE{{Kind: 0, SID: users, Mask: 0x20019}}
	if err := validateRegistryDescriptor("S-1-5-32-544", read, ""); err != nil {
		t.Fatal("read-only registry ACL rejected", err)
	}
	if validateRegistryDescriptor(users, read, "") == nil {
		t.Fatal("untrusted owner can reset the DACL")
	}
	if validateRegistryDescriptor("S-1-5-18", []protectedACE{{Kind: 9, SID: users, Mask: 0}}, "") == nil {
		t.Fatal("unclassified applicable ACE accepted")
	}
	if err := validateRegistryDescriptor("trusted-installer", []protectedACE{{Kind: 0, SID: "trusted-installer", Mask: 0x10000000}}, "trusted-installer"); err != nil {
		t.Fatal("OS-resolved TrustedInstaller rejected", err)
	}
}

func TestLegacyPreflightReservationsAndMissingRegistrationStillInspectFixedImage(t *testing.T) {
	for _, mode := range []string{"absent", "first-reserved", "both-reserved", "registry-removed", "unsafe-image"} {
		t.Run(mode, func(t *testing.T) {
			f := &legacyRegistryFixture{machine: map[string]map[string]string{}}
			if mode == "first-reserved" || mode == "both-reserved" {
				f.machine[registryFixtureKey(0x100, builderFixtureInstall)] = map[string]string{}
			}
			if mode == "both-reserved" {
				f.machine[registryFixtureKey(0x100, builderFixtureUninstall)] = map[string]string{}
			}
			checked := 0
			err := checkLegacyUninstall(builderFixtureRoot, f, func(path string) error {
				checked++
				if path != filepath.Join(builderFixtureRoot, "Uninstall LuminaVPN.exe") {
					t.Fatal(path)
				}
				if mode == "unsafe-image" {
					return errors.New("untrusted fixed image")
				}
				if mode == "registry-removed" {
					return nil
				}
				return fs.ErrNotExist
			})
			if (err == nil) != (mode != "unsafe-image") || checked != 1 || f.closed != f.opened {
				t.Fatalf("checked=%d err=%v", checked, err)
			}
		})
	}
}

func TestLegacyPreflightRejectsShortcutTraversalBeforeOldUninstaller(t *testing.T) {
	for _, name := range []string{"ShortcutName", "MenuDirectory"} {
		f := normalLegacyFixture()
		f.machine[registryFixtureKey(0x100, builderFixtureInstall)][name] = `..\..\unrelated`
		if checkLegacyUninstall(builderFixtureRoot, f, func(string) error { t.Fatal("unsafe metadata reached executable check"); return nil }) == nil {
			t.Fatal("unsafe legacy shortcut path accepted")
		}
	}
}

func TestMissingLegacyImageRequiresAbsentOrFullyRetiredServiceState(t *testing.T) {
	if err := missingLegacyImagePreflight(installJournal{}, false, nil); err != nil {
		t.Fatal(err)
	}
	_, j := journalFixture()
	if missingLegacyImagePreflight(j, true, nil) == nil {
		t.Fatal("pending bootstrap lost its uninstaller")
	}
	j = provisionedJournal(j)
	j.Phase = "complete"
	if missingLegacyImagePreflight(j, true, nil) == nil {
		t.Fatal("active complete installation lost its uninstaller")
	}
	_, retired := retireJournalFixture()
	if missingLegacyImagePreflight(retired, true, nil) == nil {
		t.Fatal("pending retirement lost its uninstaller")
	}
	retired.Phase = "complete"
	if err := missingLegacyImagePreflight(retired, true, nil); err != nil {
		t.Fatal(err)
	}
	if missingLegacyImagePreflight(retired, true, errors.New("unreadable state")) == nil {
		t.Fatal("unknown state accepted")
	}
}
