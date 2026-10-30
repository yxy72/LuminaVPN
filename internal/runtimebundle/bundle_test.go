package runtimebundle

import (
	"crypto/sha256"
	"encoding/hex"
	"netlaunch/internal/securefile"
	"netlaunch/internal/testutil"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVerifiedCopyAndTampering(t *testing.T) {
	dir := testutil.PrivateTempDir(t)
	os.Chmod(dir, 0700)
	os.Mkdir(filepath.Join(dir, "bin"), 0700)
	m := Manifest{Version: 1, OS: runtime.GOOS, Arch: runtime.GOARCH}
	for _, name := range required(runtime.GOOS) {
		if e := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0700); e != nil {
			t.Fatal(e)
		}
		b := []byte("dummy component " + name)
		os.WriteFile(filepath.Join(dir, name), b, 0700)
		h := sha256.Sum256(b)
		m.Files = append(m.Files, File{name, hex.EncodeToString(h[:])})
	}
	if e := securefile.Write(filepath.Join(dir, "manifest.json"), m); e != nil {
		t.Fatal(e)
	}
	if _, e := Verify(dir); e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(testutil.PrivateTempDir(t), "copy")
	if e := Copy(dir, dest); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(dir, required(runtime.GOOS)[0]), []byte("changed"), 0700)
	if _, e := Verify(dir); e == nil {
		t.Fatal("modified binary accepted")
	}
	m.Files[0].Path = "../escape"
	if e := securefile.Write(filepath.Join(dir, "manifest.json"), m); e != nil {
		t.Fatal(e)
	}
	if _, e := Verify(dir); e == nil {
		t.Fatal("path traversal accepted")
	}
}
