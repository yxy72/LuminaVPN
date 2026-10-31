//go:build darwin || windows

package engine

import "testing"

func TestVPNFailureClassificationNeverCopiesPrivateOutput(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"Cookie: secret-token\nHTTP/1.1 401 Unauthorized", "authentication_rejected"},
		{"NetLaunch: VPN hook interface mismatch private-value", "hook_failed"},
		{"dyld: Library not loaded: /private/runtime/libssl\nsecret-token", "runtime_load_failed"},
		{"NetLaunch: child launch gate expired\nsecret-token", "child_gate_expired"},
		{"unknown failure: secret-token", "pending_or_unclassified"},
	} {
		if got := vpnFailureCode(tc.input); got != tc.want {
			t.Fatal(got, tc.want)
		}
	}
}
