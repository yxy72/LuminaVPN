package winservice

import "testing"

func TestRegistryCreatorOwnerInheritanceTemplate(t *testing.T) {
	const system = "S-1-5-18"
	const user = "S-1-5-21-101-102-103-1001"
	for _, test := range []struct {
		name  string
		owner string
		entry protectedACE
		allow bool
	}{
		{
			name: "native creator owner CI without IO", owner: system,
			entry: protectedACE{Kind: 0, Flags: 0x02, Mask: 0xF003F, SID: "S-1-3-0"}, allow: true,
		},
		{
			name: "template does not trust an untrusted owner", owner: user,
			entry: protectedACE{Kind: 0, Flags: 0x02, Mask: 0xF003F, SID: "S-1-3-0"},
		},
		{
			name: "resolved creator remains an actual writer", owner: system,
			entry: protectedACE{Kind: 0, Flags: 0x12, Mask: 0xF003F, SID: user},
		},
		{
			name: "terminal server user remains rejected", owner: system,
			entry: protectedACE{Kind: 0, Mask: 0x3001F, SID: "S-1-5-13"},
		},
		{
			name: "everyone is not an inheritance placeholder", owner: system,
			entry: protectedACE{Kind: 0, Flags: 0x02, Mask: 0xF003F, SID: "S-1-1-0"},
		},
		{
			name: "unknown SID remains rejected", owner: system,
			entry: protectedACE{Kind: 0, Flags: 0x02, Mask: 0xF003F, SID: "S-1-5-21-201-202-203-1001"},
		},
		{
			name: "owner rights is not creator owner", owner: system,
			entry: protectedACE{Kind: 0, Flags: 0x02, Mask: 0xF003F, SID: "S-1-3-4"},
		},
		{
			name: "noninheritable creator owner stays conservative", owner: system,
			entry: protectedACE{Kind: 0, Mask: 0xF003F, SID: "S-1-3-0"},
		},
		{
			name: "unknown ACE kind is not a template", owner: system,
			entry: protectedACE{Kind: 9, Flags: 0x02, Mask: 0xF003F, SID: "S-1-3-0"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateRegistryDescriptor(test.owner, []protectedACE{test.entry}, "")
			if (err == nil) != test.allow {
				t.Fatalf("allow=%v, error=%v", test.allow, err)
			}
		})
	}
}

func TestRegistryCreatorOwnerTemplateDoesNotHideActualWriter(t *testing.T) {
	entries := []protectedACE{
		{Kind: 0, Flags: 0x02, Mask: 0xF003F, SID: "S-1-3-0"},
		{Kind: 0, Mask: 0x3001F, SID: "S-1-5-13"},
	}
	if validateRegistryDescriptor("S-1-5-18", entries, "") == nil {
		t.Fatal("inheritance template hid a real applicable writer")
	}
}

func TestRegistryAncestorRightsDoNotGrantProtectedChildRights(t *testing.T) {
	const system = "S-1-5-18"
	const users = "S-1-5-32-545"
	for _, test := range []struct {
		name           string
		mask           uint32
		parentCreates  bool
		allow, creates bool
	}{
		{"terminal server parent metadata rights", 0x3001F, false, true, true},
		{"same rights with replaceable ancestor", 0x3001F, true, false, false},
		{"set value is local", 2, true, true, false},
		{"create sibling is local", 4, true, true, true},
		{"generic write can create sibling", 0x40000000, false, true, true},
		{"DACL can propagate", 0x40000, false, false, false},
		{"owner can reset DACL", 0x80000, false, false, false},
		{"generic all", 0x10000000, false, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			entries := []protectedACE{{Kind: 0, SID: users, Mask: test.mask}}
			creates, err := validateRegistryAncestor(system, entries, "", test.parentCreates)
			if (err == nil) != test.allow || (err == nil && creates != test.creates) {
				t.Fatalf("creates=%v err=%v", creates, err)
			}
			if validateRegistryDescriptor(system, entries, "") == nil {
				t.Fatal("ancestor exception leaked to the product leaf")
			}
		})
	}
	if _, err := validateRegistryAncestor(users, nil, "", false); err == nil {
		t.Fatal("untrusted ancestor owner accepted")
	}
}
