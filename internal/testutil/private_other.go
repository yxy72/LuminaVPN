//go:build !windows

package testutil

import (
	"os"
	"testing"
)

func PrivateTempDir(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if e := os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}
func MakePublic(t *testing.T, path string) {
	t.Helper()
	if e := os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
}
