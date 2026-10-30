//go:build !windows

package runtimebundle

func checkLibraries(string) ([]LibraryCheck, error) { return nil, nil }
