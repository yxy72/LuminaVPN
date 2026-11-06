package winservice

import "testing"

func TestProtectedACLRejectsUnknownAllowAndDeleteChild(t *testing.T) {
	for _, entries := range [][]protectedACE{{{Kind: 5, Mask: 0x10000000, SID: "S-1-5-21-1"}}, {{Kind: 0, Mask: 0x40, SID: "S-1-5-21-1"}}, {{Kind: 0, Mask: 0x40000, SID: "S-1-5-21-1"}}} {
		if validateProtectedDescriptor(true, entries) == nil {
			t.Fatal("untrusted installed-path replacement rights accepted")
		}
	}
	if validateProtectedDescriptor(false, []protectedACE{{Kind: 0, Mask: 0x10000000, SID: "S-1-5-18"}}) == nil {
		t.Fatal("untrusted owner can replace DACL")
	}
}
func TestProtectedACLAllowsReadAndIgnoresInheritOnlyForCurrentObject(t *testing.T) {
	entries := []protectedACE{{Kind: 0, Mask: 0x10000000, SID: "S-1-5-18"}, {Kind: 0, Mask: 0x120089, SID: "S-1-5-32-545"}, {Kind: 0, Flags: 8, Mask: 0x10000000, SID: "S-1-3-0"}}
	if err := validateProtectedDescriptor(true, entries); err != nil {
		t.Fatal(err)
	}
}
func TestAncestorMayAllowSiblingCreationButCannotReplaceInstalledChild(t *testing.T) {
	if err := validateDescriptorMask(true, []protectedACE{{Kind: 0, Mask: 4, SID: "S-1-5-32-545"}}, ancestorReplaceMask); err != nil {
		t.Fatal("safe ProgramData sibling creation was refused")
	}
	if err := validateDescriptorMask(true, []protectedACE{{Kind: 0, Mask: 64, SID: "S-1-5-32-545"}}, ancestorReplaceMask); err == nil {
		t.Fatal("ancestor delete-child can replace protected installed tree")
	}
}
func TestOnlyIndependentlyResolvedInstallerWriterIsAllowed(t *testing.T) {
	entries := []protectedACE{{Kind: 0, Mask: 0x10000000, SID: "verified-trusted-installer"}}
	if validateDescriptorMask(true, entries, protectedWriteMask) == nil {
		t.Fatal("unverified service SID writer trusted")
	}
	if err := validateDescriptorWriters(true, entries, protectedWriteMask, map[string]bool{"verified-trusted-installer": true}); err != nil {
		t.Fatal("OS-resolved TrustedInstaller authority was rejected", err)
	}
}
