//go:build windows

package winservice

// The public preflight only reads native registry objects and the fixed file.
// Execution remains installer-owned; no registry string becomes a Go command.
func legacyUninstallPreflight(root string) error {
	return checkLegacyUninstall(root, windowsLegacyRegistry{}, (WindowsProtectedFiles{Root: root}).validatePath)
}
