package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"netlaunch/internal/runtimebundle"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPortableChineseNamesAndExplicitContents(t *testing.T) {
	root := filepath.Join(t.TempDir(), "NetLaunch")
	for _, name := range entries {
		p := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(p), 0700)
		if e := os.WriteFile(p, []byte("fixture"), 0755); e != nil {
			t.Fatal(e)
		}
	}
	os.WriteFile(filepath.Join(root, "session.json"), []byte("must never be archived"), 0600)
	archive := filepath.Join(t.TempDir(), "package.zip")
	if e := packageZIP(root, archive); e != nil {
		t.Fatal(e)
	}
	z, e := zip.OpenReader(archive)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	if len(z.File) != len(entries) {
		t.Fatal("unexpected archive files")
	}
	found := false
	for _, f := range z.File {
		if strings.HasSuffix(f.Name, "/停止与恢复.command") {
			found = true
			if f.Flags&0x800 == 0 {
				t.Fatal("missing UTF-8 ZIP flag")
			}
			if f.Mode().Perm()&0100 == 0 {
				t.Fatal("lost executable mode")
			}
		}
		if strings.HasSuffix(f.Name, "session.json") {
			t.Fatal("secret was collected")
		}
	}
	if !found {
		t.Fatal("Chinese entry was corrupted")
	}
}

func TestWindowsPackageExcludesUnlistedPrivateFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "NetLaunch-Windows")
	write := func(name string, b []byte) {
		t.Helper()
		p := filepath.Join(root, name)
		if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	for _, name := range []string{"netlaunch.exe", "README.md", "THIRD_PARTY.md", "licenses/golang-x-sys.txt", "examples/policy.json", "runtime/notices/Go-LICENSE", "runtime/notices/mihomo-LICENSE", "runtime/notices/yaml-LICENSE", "runtime/notices/openconnect/COPYING.LGPL", "runtime/notices/windows-components.txt"} {
		write(name, []byte("fixture"))
	}
	m := runtimebundle.Manifest{Version: 1, OS: "windows", Arch: "amd64"}
	data := []byte("fixed runtime fixture")
	digest := sha256.Sum256(data)
	for _, name := range []string{"bin/mihomo.exe", "bin/openconnect.exe", "bin/wintun.dll", "certs/ca-bundle.crt"} {
		write("runtime/"+name, data)
		m.Files = append(m.Files, runtimebundle.File{Path: name, SHA256: hex.EncodeToString(digest[:])})
	}
	b, _ := json.Marshal(m)
	write("runtime/manifest.json", b)
	write("session.json", []byte("private"))
	write("runtime/session.json", []byte("private"))
	archive := filepath.Join(t.TempDir(), "windows.zip")
	if e := packageWindowsZIP(root, archive); e != nil {
		t.Fatal(e)
	}
	z, e := zip.OpenReader(archive)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	for _, f := range z.File {
		if strings.Contains(f.Name, "session.json") {
			t.Fatal("private data archived")
		}
	}
	m.Files = append(m.Files, runtimebundle.File{Path: "session.json", SHA256: hex.EncodeToString(digest[:])})
	write("runtime/session.json", data)
	b, _ = json.Marshal(m)
	write("runtime/manifest.json", b)
	if e := packageWindowsZIP(root, archive); e == nil {
		t.Fatal("runtime manifest collected arbitrary file")
	}
}
