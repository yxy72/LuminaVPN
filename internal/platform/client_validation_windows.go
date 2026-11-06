//go:build windows && windows_client && windows_client_validation

package platform

// This is an experiment build boundary, not a renderer preference. Installed
// service and fixed helper both reject Daily in this build.
const WindowsClientValidationOnly = true
