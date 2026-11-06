package engine

import (
	"errors"
	"time"

	"netlaunch/internal/auth"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
)

var errVPNAuthenticationRequired = errors.New("VPN session rejected or expired; run auth")

type vpnPolicyFailure struct{ code string }

func (e *vpnPolicyFailure) Error() string { return "VPN cannot reconnect automatically: " + e.code }
func vpnTerminalFailure(reason string) error {
	switch reason {
	case "child_gate_expired", "runtime_load_failed", "hook_failed", "permission_denied", "stdin_failed", "tun_failed", "certificate_rejected", "exit_observation_failed":
		return &vpnPolicyFailure{code: reason}
	default:
		return &vpnPolicyFailure{code: "failure_classification_invalid"}
	}
}
func runtimeFailureReason(err error) string {
	if errors.Is(err, errVPNAuthenticationRequired) {
		return "authentication_required"
	}
	var failure *vpnPolicyFailure
	if errors.As(err, &failure) {
		return "vpn_" + failure.code
	}
	return "startup_or_runtime_failed"
}

func requireVPNAuthentication(session auth.Session, vpn policy.VPN, now time.Time) error {
	if session.Validate(vpn) != nil || !session.ValidAt(now) {
		return errVPNAuthenticationRequired
	}
	return nil
}

type vpnAttempt struct {
	PID   int
	Birth string
}

// vpnRetry contains only platform-independent decisions. Native code must close
// ingress, revoke leases and recover its owned resources before acting on Due.
type vpnRetry struct {
	AuthenticationRequired bool
	Failures               int
	NextAttempt            time.Time
	lastFailure            vpnAttempt
	stableSince            time.Time
	fatalReason            string
}

func (r *vpnRetry) Failed(now time.Time, child Child, reason string) error {
	if r.fatalReason != "" {
		return vpnTerminalFailure(r.fatalReason)
	}
	id := vpnAttempt{child.PID, child.Birth}
	if id == r.lastFailure && id.PID != 0 {
		return nil
	}
	r.lastFailure = id
	r.stableSince = time.Time{}
	if reason == "authentication_rejected" {
		r.AuthenticationRequired = true
		r.NextAttempt = time.Time{}
		return nil
	}
	switch reason {
	case "connection_failed", "pending_or_unclassified", "vpn_process_exited":
		// Unknown exits stay closed and retry with bounded frequency. Native
		// identity/ownership errors never enter this path.
	default:
		r.fatalReason = reason
		return vpnTerminalFailure(reason)
	}
	if r.AuthenticationRequired {
		return nil
	}
	if r.Failures < 4 {
		r.Failures++
	}
	delay := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, time.Minute}[r.Failures-1]
	r.NextAttempt = now.Add(delay)
	return nil
}
func (r *vpnRetry) Due(now time.Time) bool {
	return !r.AuthenticationRequired && r.fatalReason == "" && !now.Before(r.NextAttempt)
}
func (r *vpnRetry) Attempted(now time.Time) {
	r.NextAttempt = now.Add(10 * time.Second)
	r.stableSince = time.Time{}
}
func (r *vpnRetry) FreshAuthentication(now time.Time) { *r = vpnRetry{NextAttempt: now} }
func (r *vpnRetry) NetworkChanged(now time.Time) {
	r.Failures, r.NextAttempt, r.stableSince = 0, now, time.Time{}
}
func (r *vpnRetry) Ready(now time.Time, ready bool) {
	if !ready {
		r.stableSince = time.Time{}
		return
	}
	if r.stableSince.IsZero() {
		r.stableSince = now
	}
	if now.Sub(r.stableSince) >= 30*time.Second {
		r.Failures = 0
	}
}

type childExit struct {
	identity platform.Identity
	done     chan struct{}
	code     uint32
	reason   string
	err      error
}
type childExitTracker struct{ exits map[string]*childExit }

// Only the coordinator accesses the map. A waiter publishes to its own entry;
// replacing or clearing an attempt prevents any late result from being reused.
func (g *childExitTracker) trackExitReason(role string, id platform.Identity, wait func() (uint32, string, error)) {
	if g.exits == nil {
		g.exits = make(map[string]*childExit)
	}
	result := &childExit{identity: id, done: make(chan struct{})}
	g.exits[role] = result
	go func() { result.code, result.reason, result.err = wait(); close(result.done) }()
}
func (g *childExitTracker) trackExit(role string, id platform.Identity, wait func() (uint32, error)) {
	g.trackExitReason(role, id, func() (uint32, string, error) {
		code, err := wait()
		return code, windowsVPNExitReason(role, code, err, "vpn_process_exited"), err
	})
}

// Only the Windows adapter uses this exit-code contract. Darwin provides a
// classification from its attempt-local log, tested by the same TLS fixture.
func windowsVPNExitReason(role string, code uint32, err error, logReason string) string {
	if role == "vpn" && err == nil && code == 2 {
		return "authentication_rejected"
	}
	return logReason
}
func (g *childExitTracker) childExit(role string) (*childExit, bool) {
	result := g.exits[role]
	if result == nil {
		return nil, false
	}
	select {
	case <-result.done:
		return result, true
	default:
		return nil, false
	}
}
func (g *childExitTracker) vpnAuthenticationRejected() bool {
	result, complete := g.childExit("vpn")
	return complete && result.err == nil && result.reason == "authentication_rejected"
}
func (g *childExitTracker) failure(c Child) (string, bool) {
	result, complete := g.childExit("vpn")
	if !complete || result.identity.PID != c.PID || result.identity.Birth != c.Birth {
		return "", false
	}
	if c.Native != nil && *c.Native != result.identity {
		return "", false
	}
	if result.err != nil {
		return "exit_observation_failed", true
	}
	return result.reason, true
}
func latestVPN(s State) (Child, bool) {
	for i := len(s.Children) - 1; i >= 0; i-- {
		if s.Children[i].Role == "vpn" {
			return s.Children[i], true
		}
	}
	return Child{}, false
}

func vpnRecoveryPhase(r *vpnRetry) string {
	if r.AuthenticationRequired {
		return "authentication_required"
	}
	return "reconnecting"
}
func markVPNRecovery(s *State, r *vpnRetry) {
	s.Phase = vpnRecoveryPhase(r)
	if r.AuthenticationRequired {
		s.Error = errVPNAuthenticationRequired.Error()
	} else {
		s.Error = "VPN unavailable; waiting for reconnect"
	}
}
