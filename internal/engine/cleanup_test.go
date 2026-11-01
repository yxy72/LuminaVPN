package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCleanupPreservesRecoveryAndPreviewDoesNotDelete(t *testing.T) {
	root := t.TempDir()
	keep := []string{"state.json", "run-spec.json", "network.json", "STOP", "netlaunch.exe", "netlaunch", "manifest.json", "recovery.lock", "status.json", "unknown.bin"}
	for _, name := range append(keep, "vpn-private.log", "auth.json") {
		if err := os.WriteFile(filepath.Join(root, name), []byte("evidence"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "runtime", "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "runtime", "bin", "core"), []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := planCleanupTree(root)
	if err != nil {
		t.Fatal(err)
	}
	defer p.root.Close()
	if p.files != 3 || p.bytes != 23 {
		t.Fatal(p.files, p.bytes)
	}
	if _, err := os.Stat(filepath.Join(root, "auth.json")); err != nil {
		t.Fatal("preview deleted payload", err)
	}
	if err := p.apply(); err != nil {
		t.Fatal(err)
	}
	for _, name := range keep {
		if b, err := os.ReadFile(filepath.Join(root, name)); err != nil || string(b) != "evidence" {
			t.Fatal("lost recovery evidence", name, err)
		}
	}
	for _, name := range []string{"runtime", "auth.json", "vpn-private.log"} {
		if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatal("payload retained", name, err)
		}
	}
	if err := p.apply(); err != nil {
		t.Fatal("retry not idempotent", err)
	}
}

func TestCleanupRejectsLinksAndDoesNotFollowReplacedPayload(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	sentinel := filepath.Join(outside, "evidence")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "runtime")
	if err := os.Symlink(outside, link); err != nil {
		t.Skip("symlink unavailable", err)
	}
	if p, err := planCleanupTree(root); err == nil {
		p.root.Close()
		t.Fatal("accepted symlink")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(link, 0700); err != nil {
		t.Fatal(err)
	}
	p, err := planCleanupTree(root)
	if err != nil {
		t.Fatal(err)
	}
	defer p.root.Close()
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := p.apply(); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(sentinel); err != nil || string(b) != "keep" {
		t.Fatal("escaped root", err)
	}
}
