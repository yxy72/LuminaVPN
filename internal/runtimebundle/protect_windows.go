//go:build windows

package runtimebundle

import "netlaunch/internal/securefile"

func sealCopy(path string) error { return securefile.ProtectFile(path) }
