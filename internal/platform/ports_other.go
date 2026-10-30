//go:build !darwin

package platform

func deferPortBindCheck(error) bool { return false }
