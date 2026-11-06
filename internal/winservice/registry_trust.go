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
	return validateDescriptorWriters(trusted, entries, registryWriteMask, additional)
}
