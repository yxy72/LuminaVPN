//go:build !windows

package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
)

func legacyCacheFixture(t *testing.T) (string, policy.VPN, Session) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	v := policy.VPN{Server: "https://vpn.example.com:4433", EndpointIPv4: "192.0.2.1"}
	s := Session{Cookie: "fixture-session", Host: "vpn.example.com", Fingerprint: "sha256:abc123", Created: time.Now().UTC().Add(-5 * time.Minute)}
	return dir, v, s
}

// Build the pre-Windows-refactor JSON independently of cacheEncode/cached so
// these tests also detect accidental changes to the non-Windows disk format.
func legacyCacheJSON(s Session) []byte {
	return []byte(fmt.Sprintf(`{"server":"https://vpn.example.com:4433","endpoint":"192.0.2.1","session":{"cookie":"fixture-session","host":"vpn.example.com","fingerprint":"sha256:abc123","created":%q}}`, s.Created.Format(time.RFC3339Nano)))
}

func assertLegacySession(t *testing.T, got, want Session) {
	t.Helper()
	if got.Cookie != want.Cookie || got.Host != want.Host || got.Fingerprint != want.Fingerprint || !got.Created.Equal(want.Created) {
		t.Fatal("legacy session changed or its creation time was extended")
	}
}

func TestLegacyCacheVPNMismatchPreservesReusableSession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*policy.VPN)
	}{
		{"server", func(v *policy.VPN) { v.Server = "https://other.example.com:4433" }},
		{"server port", func(v *policy.VPN) { v.Server = "https://vpn.example.com:4434" }},
		{"endpoint", func(v *policy.VPN) { v.EndpointIPv4 = "192.0.2.2" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, correct, want := legacyCacheFixture(t)
			path := filepath.Join(dir, "session.json")
			original := legacyCacheJSON(want)
			if err := securefile.Bytes(path, original); err != nil {
				t.Fatal(err)
			}
			wrong := correct
			tc.change(&wrong)
			if _, ok := Load(dir, wrong); ok {
				t.Fatal("cache accepted a different VPN")
			}
			retained, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(retained, original) {
				t.Fatalf("VPN mismatch removed or rewrote the recoverable cache: %v", err)
			}
			got, ok := Load(dir, correct)
			if !ok {
				t.Fatal("the original VPN could no longer reuse its session")
			}
			assertLegacySession(t, got, want)
		})
	}
}

func TestLegacyCacheMalformedJSONIsPreserved(t *testing.T) {
	for _, payload := range []string{`{"server":`, `not-json`, `null`} {
		t.Run(payload, func(t *testing.T) {
			dir, v, _ := legacyCacheFixture(t)
			path := filepath.Join(dir, "session.json")
			if err := securefile.Bytes(path, []byte(payload)); err != nil {
				t.Fatal(err)
			}
			if _, ok := Load(dir, v); ok {
				t.Fatal("malformed cache was accepted")
			}
			retained, err := os.ReadFile(path)
			if err != nil || string(retained) != payload {
				t.Fatalf("malformed cache was removed or rewritten: %v", err)
			}
		})
	}
}

func TestLegacyCacheInvalidAgeIsRemoved(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset time.Duration
	}{
		{"expired", -MaxAge - time.Minute},
		{"future", time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, v, s := legacyCacheFixture(t)
			s.Created = time.Now().UTC().Add(tc.offset)
			path := filepath.Join(dir, "session.json")
			if err := securefile.Bytes(path, legacyCacheJSON(s)); err != nil {
				t.Fatal(err)
			}
			if _, ok := Load(dir, v); ok {
				t.Fatal("invalid-age cache was reused")
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("invalid-age cache was not removed: %v", err)
			}
		})
	}
}

func TestLegacyCacheLayoutAndCreationTimeRemainUnchanged(t *testing.T) {
	dir, v, want := legacyCacheFixture(t)
	if err := Save(dir, v, want); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "session.json")
	original, err := securefile.Read(path, 128<<10, true)
	if err != nil {
		t.Fatal(err)
	}
	var gotLayout, wantLayout any
	if err := json.Unmarshal(original, &gotLayout); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(legacyCacheJSON(want), &wantLayout); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotLayout, wantLayout) {
		t.Fatal("non-Windows cache no longer has the legacy JSON layout")
	}
	for range 2 {
		got, ok := Load(dir, v)
		if !ok {
			t.Fatal("valid legacy cache was rejected")
		}
		assertLegacySession(t, got, want)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatalf("reading a valid cache rewrote it: %v", err)
	}
}
