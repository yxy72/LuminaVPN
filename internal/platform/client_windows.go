//go:build windows && windows_client

package platform

// WindowsClientBuild is explicit. Its native operations are still authorized by
// the installed service; an ordinary tagged CLI cannot create an implicit run.
const WindowsClientBuild = true
