//go:build !windows

package auth

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"netlaunch/internal/testutil"
)

func TestLegacyCacheMismatchDoesNotDeleteTheOriginalSession(t *testing.T) {
	dir := testutil.PrivateTempDir(t)
	s, err := Parse(output("vpn.example.com"), vpn)
	if err != nil {
		t.Fatal(err)
	}
	if err = Save(dir, vpn, s); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "session.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := vpn
	changed.EndpointIPv4 = "192.0.2.2"
	if _, ok := Load(dir, changed); ok {
		t.Fatal("cache crossed a VPN endpoint binding")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("mismatching read deleted or rewrote the original cache", err)
	}
	got, ok := Load(dir, vpn)
	if !ok || got.Cookie != s.Cookie || got.Host != s.Host || got.Fingerprint != s.Fingerprint || !got.Created.Equal(s.Created) {
		t.Fatal("the original endpoint cannot reuse its unchanged session")
	}
	if err = os.WriteFile(path, []byte("not JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok = Load(dir, vpn); ok {
		t.Fatal("invalid cache accepted")
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "not JSON" {
		t.Fatal("legacy parse failure deleted cache", err)
	}
}
