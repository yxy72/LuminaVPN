package engine

import (
	"context"
	"encoding/json"
	"netlaunch/internal/policy"
	"strings"
	"testing"
	"time"

	"netlaunch/internal/dnswire"
	"netlaunch/internal/platform"
)

func TestStoppedAuthenticationFailureKeepsActionableReason(t *testing.T) {
	s := State{Phase: "stopped", RecoveryReason: "authentication_required"}
	status := publicStatus(s, time.Now())
	if status.Phase != "stopped" || status.Lifecycle != "stopped" || !NeedsAuthentication(status) || status.Channels["company"].NextAction != "run_auth" {
		t.Fatal("startup authentication failure lost during cleanup", status)
	}
	s.Phase = "recovery_failed"
	status = publicStatus(s, time.Now())
	if NeedsAuthentication(status) || status.Channels["company"].NextAction != "run_down" {
		t.Fatal("recovery conflict lost priority", status)
	}
}

func healthyState(now time.Time) State {
	s := State{Phase: "ready", LastReady: now, Personal: "node-a", VPN: VPNSession{Bootstrap: true, Generation: "generation-a"}}
	s.Manifest.Network = platform.Network{Interface: "fixture-interface", Address: "192.0.2.10", Gateway: "192.0.2.1"}
	s.Manifest.Config.Company.Domains = []string{"service.corp.example"}
	s.Leases = []dnswire.Answer{{Domain: "service.corp.example", IP: "192.0.2.20", ExpiresAt: now.Add(time.Minute)}}
	s.Channels = map[string]ChannelHealth{}
	for _, name := range []string{"company", "personal", "direct"} {
		s.Channels[name] = ChannelHealth{ChannelStatus: ChannelStatus{State: "ready", CheckedAt: now, Reason: "path_verified"}, Generation: s.VPN.Generation, Node: s.Personal, Network: s.Manifest.Network}
	}
	return s
}

func TestPersonalFailureDoesNotMisreportCompany(t *testing.T) {
	now := time.Now()
	s := healthyState(now)
	s.Phase = "degraded"
	s.Personal = "REJECT"
	out := publicStatus(s, now)
	if out.Company != "ready" || out.Channels["personal"].State != "unavailable" || out.Channels["direct"].State != "ready" || out.Lifecycle != "running" {
		t.Fatal(out)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"192.0.2.", "fixture-interface", "service.corp.example", "generation-a"} {
		if strings.Contains(string(b), private) {
			t.Fatal("private health identity exported")
		}
	}
}

func TestHealthDoesNotSurviveStopNetworkOrGenerationChanges(t *testing.T) {
	now := time.Now()
	for _, phase := range []string{"stopping", "stopped", "recovery_failed", "network_unavailable"} {
		s := healthyState(now)
		before := s
		s.Phase = phase
		invalidateChannelHealth(before, &s)
		if len(s.Channels) != 0 {
			t.Fatal("retained stale health", phase)
		}
		out := publicStatus(s, now)
		for _, h := range out.Channels {
			if h.State == "ready" {
				t.Fatal(phase, out)
			}
		}
	}
	s := healthyState(now)
	before := s
	s.VPN.Generation = "generation-b"
	invalidateChannelHealth(before, &s)
	if publicStatus(s, now).Company == "ready" {
		t.Fatal("old generation shown as ready")
	}
	s = healthyState(now)
	s.Manifest.Network.Address = "192.0.2.11"
	if publicStatus(s, now).Company == "ready" || publicStatus(s, now).Channels["direct"].State == "ready" {
		t.Fatal("old network evidence reused")
	}
}

func TestLeaseExpiryAuthenticationAndStaleChecksOverrideSuccess(t *testing.T) {
	now := time.Now()
	s := healthyState(now)
	if publicStatus(s, now.Add(61*time.Second)).Company == "ready" {
		t.Fatal("expired company lease remains ready")
	}
	s.Phase = "authentication_required"
	out := publicStatus(s, now)
	if out.Channels["company"].NextAction != "run_auth" || out.Channels["personal"].State != "ready" {
		t.Fatal(out)
	}
	s = healthyState(now)
	out = publicStatus(s, now.Add(91*time.Second))
	if out.Phase == "ready" || out.Channels["direct"].State != "unknown" {
		t.Fatal(out)
	}
	s.Channels = nil
	if publicStatus(s, now).Company == "ready" {
		t.Fatal("legacy state without evidence guessed healthy")
	}
}

func TestChannelBatchRetainsFailureAndClassifiesWrappedErrors(t *testing.T) {
	now := time.Now()
	failure := describeProbeFailure(policy.Probe{Channel: "personal", URL: "https://target.example/"}, tlsProbeFailure(context.DeadlineExceeded))
	observed := observeChannel(ChannelStatus{}, failure, now, policy.Probe{Channel: "personal"})
	observed = observeChannel(observed, nil, now.Add(time.Second), policy.Probe{Channel: "personal"})
	if observed.State != "unavailable" || observed.Reason != "tls_timeout" {
		t.Fatal(observed)
	}
	// The next independent batch can recover after all its targets pass.
	recovered := observeChannel(ChannelStatus{}, nil, now.Add(2*time.Second), policy.Probe{Channel: "personal"})
	if recovered.State != "ready" {
		t.Fatal(recovered)
	}
}

func TestPersonalFailureReasonSurvivesSelectionInvalidation(t *testing.T) {
	now := time.Now()
	s := healthyState(now)
	before := s
	s.Personal = "REJECT"
	personalUnavailable(&s, "tls_certificate_invalid")
	invalidateChannelHealth(before, &s)
	if got := publicStatus(s, now).Channels["personal"].Reason; got != "tls_certificate_invalid" {
		t.Fatal(got)
	}
	if publicStatus(s, now).Company != "ready" {
		t.Fatal("personal error invalidated company")
	}
}

func TestPublicStatusAgesWithoutCoordinatorAndPreservesOriginalSnapshot(t *testing.T) {
	now := time.Now()
	out := publicStatus(healthyState(now), now)
	aged := RefreshStatus(out, now.Add(2*time.Minute))
	if aged.Phase != "degraded" || aged.Company == "ready" {
		t.Fatal(aged)
	}
	if out.Company != "ready" || out.Channels["direct"].State != "ready" {
		t.Fatal("mutated input")
	}
}
