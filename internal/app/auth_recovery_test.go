package app

import (
	"testing"
	"time"

	"netlaunch/internal/auth"
	"netlaunch/internal/engine"
	"netlaunch/internal/policy"
	"netlaunch/internal/testutil"
)

func TestAuthenticationAfterStartupRecoveryReusesOnlyNewSession(t *testing.T) {
	profile := testutil.PrivateTempDir(t)
	cfg := policy.Config{VPN: policy.VPN{Server: "https://vpn.example.org", EndpointIPv4: "192.0.2.1"}}
	now := time.Now()
	status := engine.Status{Phase: "stopped", RecoveryReason: "authentication_required", Updated: now.Add(-10 * time.Minute)}
	if !requiresFreshAuthentication(profile, cfg, status) {
		t.Fatal("missing session accepted")
	}
	session := auth.Session{Host: "vpn.example.org", Cookie: "fixture", Fingerprint: "sha256:abcd", Created: now.Add(-time.Hour)}
	if err := auth.Save(profile, cfg.VPN, session); err != nil {
		t.Fatal(err)
	}
	if !requiresFreshAuthentication(profile, cfg, status) {
		t.Fatal("rejected session reused after cleanup")
	}
	session.Created = now.Add(-time.Minute)
	if err := auth.Save(profile, cfg.VPN, session); err != nil {
		t.Fatal(err)
	}
	if requiresFreshAuthentication(profile, cfg, status) {
		t.Fatal("fresh explicit authentication needlessly repeated")
	}
	status.Phase = "authentication_required"
	if !requiresFreshAuthentication(profile, cfg, status) {
		t.Fatal("running rejection ignored")
	}
	status.Phase = "recovery_failed"
	if requiresFreshAuthentication(profile, cfg, status) {
		t.Fatal("authentication displaced required network recovery")
	}
}
