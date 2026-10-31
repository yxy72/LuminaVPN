//go:build !windows || !windows_validation

package platform

// WindowsValidationBuild is false for distributed and ordinary builds.
const WindowsValidationBuild = false
