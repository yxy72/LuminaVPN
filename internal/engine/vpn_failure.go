//go:build darwin || windows

package engine

import (
	"errors"
	"path/filepath"
	"strings"
)

func vpnBootstrapFailure(run string, child Child) error {
	code := vpnAttemptFailure(run, child)
	if code == "authentication_rejected" {
		return errVPNAuthenticationRequired
	}
	return errors.New("VPN bootstrap failed: " + code)
}
func vpnAttemptFailure(run string, child Child) string {
	if child.LogName == "" || filepath.Base(child.LogName) != child.LogName {
		return "pending_or_unclassified"
	}
	data, _ := readVPNLog(run, child.LogName)
	return vpnFailureCode(string(data))
}

// Only fixed classifications leave the administrator log. Never copy output
// that could contain authentication headers, cookies or peer-provided text.
func vpnFailureCode(log string) string {
	text := strings.ToLower(log)
	for _, group := range []struct {
		code    string
		matches []string
	}{
		{"child_gate_expired", []string{"child launch gate expired"}},
		{"runtime_load_failed", []string{"library not loaded", "dyld:", "error while loading shared libraries"}},
		{"hook_failed", []string{"vpn hook", "script '"}},
		{"authentication_rejected", []string{"cookie was rejected", "cookie is invalid", "authentication failed", "401 unauthorized", "403 forbidden", "no cookie"}},
		{"permission_denied", []string{"operation not permitted", "permission denied"}},
		{"stdin_failed", []string{"bad file descriptor", "failed to read cookie"}},
		{"tun_failed", []string{"failed to open tun", "failed to connect utun", "failed to open sysproto_control"}},
		{"certificate_rejected", []string{"server certificate verify failed", "certificate does not match"}},
		{"connection_failed", []string{"failed to connect", "connection refused", "connection timed out"}},
	} {
		for _, marker := range group.matches {
			if strings.Contains(text, marker) {
				return group.code
			}
		}
	}
	return "pending_or_unclassified"
}
