//go:build !windows

package runtimebundle

func sealCopy(string) error { return nil }
