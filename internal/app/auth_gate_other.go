//go:build !windows

package app

func awaitAuthentication(string) error { return nil }
