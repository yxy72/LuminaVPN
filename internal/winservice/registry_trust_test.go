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
