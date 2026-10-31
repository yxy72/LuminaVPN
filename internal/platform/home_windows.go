//go:build windows && windows_home

package platform

// WindowsHomeBuild enables the bounded home preview. It always requires a
// published wall-clock deadline, just like the shorter validation build.
const WindowsHomeBuild = true
