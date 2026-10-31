package engine

import (
	"errors"
	"strings"
	"testing"
	"time"

	"netlaunch/internal/auth"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
)

func TestVPNRetryBackoffAndStableReset(t *testing.T) {
	now := time.Unix(1000, 0)
	r := &vpnRetry{}
	for i, delay := range []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, time.Minute, time.Minute} {
		child := Child{PID: i + 1, Birth: "fixture"}
		if err := r.Failed(now, child, "connection_failed"); err != nil {
			t.Fatal(err)
		}
		want := now.Add(delay)
		if r.NextAttempt != want || r.Due(want.Add(-time.Nanosecond)) || !r.Due(want) {
			t.Fatal("incorrect retry deadline", r)
		}
		if err := r.Failed(now.Add(time.Second), child, "connection_failed"); err != nil || r.NextAttempt != want {
			t.Fatal("repeated observation restarted backoff", err)
		}
		now = want
		r.Attempted(now)
	}
	r.Ready(now, true)
	r.Ready(now.Add(29*time.Second), true)
	if r.Failures == 0 {
		t.Fatal("brief connection reset backoff")
	}
	r.Ready(now.Add(30*time.Second), true)
	if r.Failures != 0 {
		t.Fatal("stable connection did not reset backoff")
	}
	if err := r.Failed(now.Add(time.Minute), Child{PID: 10}, "vpn_process_exited"); err != nil || r.NextAttempt != now.Add(70*time.Second) {
		t.Fatal(r, err)
	}
}

func TestVPNAuthenticationLatchSurvivesNetworkChange(t *testing.T) {
	now := time.Unix(1000, 0)
	r := &vpnRetry{}
	if err := r.Failed(now, Child{PID: 1}, "authentication_rejected"); err != nil {
		t.Fatal(err)
	}
	r.NetworkChanged(now.Add(time.Minute))
	r.Ready(now, true)
	r.Ready(now.Add(time.Hour), true)
	if r.Due(now.Add(time.Hour)) || !r.AuthenticationRequired {
		t.Fatal("old rejected session retried")
	}
	s := State{Phase: "ready"}
	markVPNRecovery(&s, r)
	if s.Phase != "authentication_required" || s.Error == "" {
		t.Fatal(s)
	}
	r.FreshAuthentication(now.Add(time.Hour))
	if !r.Due(now.Add(time.Hour)) || r.AuthenticationRequired || r.Failures != 0 {
		t.Fatal("fresh authentication not accepted")
	}
	markVPNRecovery(&s, r)
	if s.Phase != "reconnecting" {
		t.Fatal(s.Phase)
	}
}

func TestVPNNativeFailuresNeverBecomeTransportRetries(t *testing.T) {
	for _, reason := range []string{"hook_failed", "permission_denied", "tun_failed", "certificate_rejected", "runtime_load_failed", "child_gate_expired", "stdin_failed", "exit_observation_failed"} {
		r := &vpnRetry{}
		now := time.Unix(1000, 0)
		if err := r.Failed(now, Child{PID: 1}, reason); err == nil {
			t.Fatal(reason)
		} else if runtimeFailureReason(err) != "vpn_"+reason {
			t.Fatal("fixed diagnostic lost", runtimeFailureReason(err))
		}
		r.NetworkChanged(now)
		if r.Due(now.Add(time.Hour)) {
			t.Fatal("native failure became retryable", reason)
		}
	}
	if reason := runtimeFailureReason(vpnTerminalFailure("private-fixture-token")); strings.Contains(reason, "private-fixture-token") {
		t.Fatal("private text escaped classification")
	}
}

func TestVPNAuthenticationFreshnessSharedByLaunchers(t *testing.T) {
	now := time.Unix(20000, 0)
	vpn := policy.VPN{Server: "https://vpn.example.org", EndpointIPv4: "192.0.2.1"}
	valid := auth.Session{Host: "vpn.example.org", Cookie: "fixture", Fingerprint: "sha256:abcd", Created: now.Add(-time.Hour)}
	if err := requireVPNAuthentication(valid, vpn, now); err != nil {
		t.Fatal(err)
	}
	for _, stamp := range []time.Time{{}, now.Add(time.Second), now.Add(-auth.MaxAge - time.Nanosecond)} {
		s := valid
		s.Created = stamp
		if !errors.Is(requireVPNAuthentication(s, vpn, now), errVPNAuthenticationRequired) {
			t.Fatal("stale session accepted", stamp)
		}
	}
	valid.Cookie = ""
	if !errors.Is(requireVPNAuthentication(valid, vpn, now), errVPNAuthenticationRequired) {
		t.Fatal("invalid session accepted")
	}
}

func TestVPNExitTrackerBindsClassificationToCurrentAttempt(t *testing.T) {
	g := &childExitTracker{}
	oldDone, newDone := make(chan struct{}), make(chan struct{})
	g.trackExitReason("vpn", platform.Identity{PID: 1, Birth: "old"}, func() (uint32, string, error) { <-oldDone; return 2, "authentication_rejected", nil })
	old := g.exits["vpn"]
	g.trackExitReason("vpn", platform.Identity{PID: 2, Birth: "new"}, func() (uint32, string, error) { <-newDone; return 1, "connection_failed", nil })
	fresh := g.exits["vpn"]
	close(oldDone)
	<-old.done
	if g.vpnAuthenticationRejected() {
		t.Fatal("late auth rejection affected new process")
	}
	if _, known := g.failure(Child{PID: 1, Birth: "old"}); known {
		t.Fatal("old result still current")
	}
	close(newDone)
	<-fresh.done
	if reason, known := g.failure(Child{PID: 2, Birth: "new"}); !known || reason != "connection_failed" {
		t.Fatal(reason, known)
	}
	if _, known := g.failure(Child{PID: 2, Birth: "reused"}); known {
		t.Fatal("PID reuse accepted")
	}
	delete(g.exits, "vpn")
	if _, known := g.failure(Child{PID: 2, Birth: "new"}); known {
		t.Fatal("cleared attempt republished")
	}
}

func TestVPNExitUsesPlatformClassificationAndNativeIdentity(t *testing.T) {
	g := &childExitTracker{}
	id := platform.Identity{PID: 10, Birth: "fixture", Executable: "fixture-binary"}
	g.trackExitReason("vpn", id, func() (uint32, string, error) { return 2, "connection_failed", nil })
	<-g.exits["vpn"].done
	if g.vpnAuthenticationRejected() {
		t.Fatal("Windows exit convention leaked into another adapter")
	}
	wrong := id
	wrong.Executable = "replacement"
	if _, known := g.failure(Child{PID: id.PID, Birth: id.Birth, Native: &wrong}); known {
		t.Fatal("native identity mismatch accepted")
	}
	if reason, known := g.failure(Child{PID: id.PID, Birth: id.Birth, Native: &id}); !known || reason != "connection_failed" {
		t.Fatal(reason, known)
	}
}
