//go:build !windows

package securefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateAtomicIO(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	p := filepath.Join(dir, "state")
	if e := Bytes(p, []byte("abc")); e != nil {
		t.Fatal(e)
	}
	if _, e := Read(p, 2, true); e == nil {
		t.Fatal("size limit ignored")
	}
	b, e := Read(p, 3, true)
	if e != nil || string(b) != "abc" {
		t.Fatal(e)
	}
	i, _ := os.Stat(p)
	if i.Mode().Perm() != 0600 {
		t.Fatal("mode")
	}
	os.Chmod(p, 0644)
	if _, e := Read(p, 3, true); e == nil {
		t.Fatal("public secret")
	}
}
func TestSymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	target := filepath.Join(dir, "target")
	Bytes(target, []byte("secret"))
	link := filepath.Join(dir, "link")
	if e := os.Symlink(target, link); e != nil {
		t.Skip(e)
	}
	if _, e := Read(link, 100, true); e == nil {
		t.Fatal("read symlink")
	}
	if e := Bytes(link, []byte("overwritten")); e == nil {
		t.Fatal("wrote symlink")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "secret" {
		t.Fatal("target modified")
	}
}
