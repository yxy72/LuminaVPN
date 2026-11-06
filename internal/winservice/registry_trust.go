package winservice

// Registry-specific rights, not the similarly numbered file access rights.
// No untrusted principal may write values, create keys/links, delete or reset
// security on a key in the execution-authority path, including an ancestor.
const registryWriteMask uint32 = 0x500D0026

func validateRegistryDescriptor(owner string, entries []protectedACE, trustedInstaller string) error {
	additional := map[string]bool{}
	if trustedInstaller != "" {
		additional[trustedInstaller] = true
	}
	trusted := owner == "S-1-5-18" || owner == "S-1-5-32-544" || (trustedInstaller != "" && owner == trustedInstaller)
	applicable := make([]protectedACE, 0, len(entries))
	for _, entry := range entries {
		// CREATOR OWNER is an inheritance placeholder, not an effective SID for
		// this key's owner (OWNER RIGHTS). A child ACE resolved to the creator's
		// actual SID must still pass the ordinary writer checks. Recognize only
		// allow templates marked CONTAINER_INHERIT, even when IO is absent.
		if entry.Kind == 0 && entry.Flags&0x02 != 0 && entry.SID == "S-1-3-0" {
			continue
		}
		applicable = append(applicable, entry)
	}
	return validateDescriptorWriters(trusted, applicable, registryWriteMask, additional)
}
