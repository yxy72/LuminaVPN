//go:build windows

package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netlaunch/internal/auth"
	"netlaunch/internal/policy"
)

func snapshotFixture(t *testing.T) (string, serviceSnapshotDependencies) {
	t.Helper()
	profile := filepath.Join(t.TempDir(), "profile")
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(profile))))
	id := hex.EncodeToString(sum[:16])
	now := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	cfg := policy.Config{Version: 1, Ports: policy.Ports{Proxy: 7890, DNS: 1053}, VPN: policy.VPN{Server: "https://vpn.example.test", EndpointIPv4: "192.0.2.1"}}
	deps := serviceSnapshotDependencies{identity: func() error { return nil }, profile: func() (string, error) { return profile, nil }, policy: func(string) (policy.Config, error) { return cfg, nil }, effective: func(_ string, c policy.Config) (policy.Config, []policy.Node, error) {
		c.PersonalRules = []policy.Rule{{Type: "DOMAIN", Value: "cached.example.test", Target: "personal"}}
		return c, []policy.Node{}, nil
	}, session: func(string, policy.VPN) (auth.Session, bool) {
		return auth.Session{Host: "vpn.example.test", Cookie: "private-session-canary", Fingerprint: "sha256:AA==", Created: now.Add(-time.Minute)}, true
	}, now: func() time.Time { return now }}
	return id, deps
}
func TestPrivateUserSnapshotKeepsEffectivePolicyAndRawRevision(t *testing.T) {
	id, deps := snapshotFixture(t)
	var out bytes.Buffer
	if err := serviceUserSnapshot(strings.NewReader(`{"profile_id":"`+id+`"}`), &out, deps); err != nil {
		t.Fatal(err)
	}
	var data ServiceUserSnapshotData
	if json.Unmarshal(bytes.TrimSpace(out.Bytes()), &data) != nil {
		t.Fatal("private snapshot protocol")
	}
	base, _ := deps.policy("")
	if len(data.Policy.PersonalRules) != 1 || len(data.SavedPolicy.PersonalRules) != 0 || data.PolicyRevision != policyRevision(data.SavedPolicy) || data.PolicyRevision != policyRevision(base) || data.PolicyRevision == policyRevision(data.Policy) || len(data.EffectiveDigest) != 64 || data.Session == nil || !data.Session.ValidAt(deps.now()) {
		t.Fatal("snapshot identity or session age drift")
	}
	if strings.Contains(out.String(), "password") || strings.Contains(out.String(), "otp") {
		t.Fatal("credential field escaped private snapshot")
	}
}
func TestPrivateUserSnapshotRejectsUnknownProfilePathsAndUnsafeIdentity(t *testing.T) {
	id, deps := snapshotFixture(t)
	for _, input := range []string{`{"profile_id":"unknown"}`, `{"profile_id":"` + id + `","path":"private-path-canary"}`, `{"profile_id":"` + id + `"} {}`, `null`, strings.Repeat("x", 4097)} {
		var out bytes.Buffer
		err := serviceUserSnapshot(strings.NewReader(input), &out, deps)
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "private-path-canary") {
			t.Fatal("unsafe snapshot input accepted")
		}
	}
	deps.identity = func() error { return errors.New("System/session-zero") }
	deps.policy = func(string) (policy.Config, error) {
		t.Fatal("policy read before real user identity")
		return policy.Config{}, nil
	}
	var out bytes.Buffer
	if serviceUserSnapshot(strings.NewReader(`{"profile_id":"`+id+`"}`), &out, deps) == nil || out.Len() != 0 {
		t.Fatal("unsafe identity accepted")
	}
}
func TestPrivateUserSnapshotCannotRenewExpiredOrFutureSession(t *testing.T) {
	for _, age := range []time.Duration{2 * time.Hour, 3 * time.Hour, -time.Minute} {
		id, deps := snapshotFixture(t)
		old := deps.session
		deps.session = func(dir string, vpn policy.VPN) (auth.Session, bool) {
			s, ok := old(dir, vpn)
			s.Created = deps.now().Add(-age)
			return s, ok
		}
		var out bytes.Buffer
		if err := serviceUserSnapshot(strings.NewReader(`{"profile_id":"`+id+`"}`), &out, deps); err != nil {
			t.Fatal(err)
		}
		var data ServiceUserSnapshotData
		if json.Unmarshal(out.Bytes(), &data) != nil || data.Session != nil {
			t.Fatal("session absolute age extended")
		}
	}
}
func TestPrivateUserSnapshotFencesConcurrentPolicyReplacement(t *testing.T) {
	id, deps := snapshotFixture(t)
	original := deps.policy
	reads := 0
	deps.policy = func(path string) (policy.Config, error) {
		cfg, err := original(path)
		reads++
		if reads == 2 {
			cfg.Personal.Domains = []string{"changed.example.test"}
		}
		return cfg, err
	}
	var out bytes.Buffer
	if serviceUserSnapshot(strings.NewReader(`{"profile_id":"`+id+`"}`), &out, deps) == nil || out.Len() != 0 {
		t.Fatal("mixed revision snapshot returned")
	}
}
