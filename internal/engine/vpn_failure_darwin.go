//go:build darwin

package engine

import (
	"errors"
	"path/filepath"
	"strings"

	"netlaunch/internal/securefile"
)

func vpnBootstrapFailure(run string) error {
	data, _ := securefile.Read(filepath.Join(private(run), "vpn-private.log"), 128<<10, true)
	return errors.New("VPN bootstrap failed: " + vpnFailureCode(string(data)))
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
