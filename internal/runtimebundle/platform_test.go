package runtimebundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsManifestPathsAndRequiredDriver(t *testing.T) {
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "bin"), 0700)
	m := Manifest{Version: 1, OS: "windows", Arch: "amd64"}
	for _, name := range required("windows") {
		if e := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0700); e != nil {
			t.Fatal(e)
		}
		b := []byte(name)
		if e := os.WriteFile(filepath.Join(root, name), b, 0600); e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(b)
		m.Files = append(m.Files, File{name, hex.EncodeToString(sum[:])})
	}
	write := func() {
		b, _ := json.Marshal(m)
		if err := os.WriteFile(filepath.Join(root, "manifest.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if _, e := VerifyFor(root, "windows", "amd64"); e != nil {
		t.Fatal(e)
	}
	if _, e := VerifyFor(root, "darwin", "arm64"); e == nil {
		t.Fatal("wrong platform accepted")
	}
	for _, bad := range []string{"bin/../openconnect.exe", "bin\\openconnect.exe", "bin/openconnect.exe:stream", "C:/openconnect.exe", "/bin/openconnect.exe"} {
		old := m.Files[0].Path
		m.Files[0].Path = bad
		write()
		if _, e := VerifyFor(root, "windows", "amd64"); e == nil {
			t.Fatal("unsafe manifest path", bad)
		}
		m.Files[0].Path = old
	}
	m.Files = m.Files[:2]
	write()
	if _, e := VerifyFor(root, "windows", "amd64"); e == nil {
		t.Fatal("missing Wintun accepted")
	}
}
