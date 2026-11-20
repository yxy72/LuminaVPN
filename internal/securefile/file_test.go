//go:build !windows

package securefile

import (
	"errors"
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

func TestReadAtomicSnapshotHandlesConcurrentPublication(t *testing.T) {
	for _, test := range []struct {
		name         string
		replacements int
		mode         os.FileMode
		want         string
		wantAttempts int
	}{
		{"reads the replacement", 1, 0600, "published", 2},
		{"rejects a public replacement", 1, 0644, "", 1},
		{"bounds retries", 3, 0600, "", 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "heartbeat.json")
			if err := Bytes(path, []byte("original")); err != nil {
				t.Fatal(err)
			}
			attempts := 0
			data, err := readAtomicSnapshot(path, 20, func(name string) (*os.File, error) {
				attempts++
				if attempts <= test.replacements {
					if err := Bytes(name, []byte("published")); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(name, test.mode); err != nil {
						t.Fatal(err)
					}
				}
				return openBoundedRead(name)
			})
			if string(data) != test.want || attempts != test.wantAttempts || (err == nil) != (test.want != "") {
				t.Fatalf("read %q, error %v, attempts %d", data, err, attempts)
			}
			if got := errors.Is(err, errReadIdentityChanged); got != (test.replacements == 3) {
				t.Fatalf("unexpected identity error: %v", err)
			}
		})
	}
}
