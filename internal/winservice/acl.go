package winservice

import "errors"

type protectedACE struct {
	Kind  byte
	Flags byte
	Mask  uint32
	SID   string
}

const protectedWriteMask uint32 = 0x40000000 | 0x10000000 | 2 | 4 | 16 | 64 | 256 | 0x10000 | 0x40000 | 0x80000
const ancestorReplaceMask uint32 = 0x10000000 | 64 | 0x10000 | 0x40000 | 0x80000

func validateProtectedDescriptor(ownerTrusted bool, entries []protectedACE) error {
	return validateDescriptorMask(ownerTrusted, entries, protectedWriteMask)
}
func validateDescriptorMask(ownerTrusted bool, entries []protectedACE, writeMask uint32) error {
	return validateDescriptorWriters(ownerTrusted, entries, writeMask, nil)
}
func validateDescriptorWriters(ownerTrusted bool, entries []protectedACE, writeMask uint32, additional map[string]bool) error {
	if !ownerTrusted {
		return errors.New("untrusted owner can replace the installed DACL")
	}
	for _, entry := range entries {
		if entry.Flags&8 != 0 {
			continue
		} // INHERIT_ONLY does not grant this object rights.
		if entry.Kind != 0 && entry.Kind != 1 {
			return errors.New("unclassified installed DACL entry")
		}
		if entry.Kind == 0 && entry.Mask&writeMask != 0 && entry.SID != "S-1-5-18" && entry.SID != "S-1-5-32-544" && !additional[entry.SID] {
			return errors.New("installed object writable or replaceable by untrusted principal")
		}
	}
	return nil
}
