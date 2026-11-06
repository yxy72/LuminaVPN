//go:build windows

package winservice

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// This opt-in observes only OS tokens and the fixed profile location. It never
// creates directories, edits ACLs/registry, installs services or starts workers.
func TestNativeUnfilteredDesktopEnrollmentReadOnly(t *testing.T) {
	if os.Getenv("NETLAUNCH_TEST_INTERACTIVE_TOKEN_READONLY") != "1" {
		t.Skip("requires an explicitly selected unfiltered interactive installer login")
	}
	binding, err := captureInstallerEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyCurrentInteractiveUser(); err != nil {
		t.Fatal(err)
	}
	var process windows.Token
	if err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &process); err != nil {
		t.Fatal(err)
	}
	defer process.Close()
	facts, err := enrollmentTokenFacts(process)
	if err != nil {
		t.Fatal(err)
	}
	if desktopTokenMode(facts) != desktopUnfilteredAdmin {
		t.Fatal("selected native login is not an unfiltered administrator")
	}
	t.Logf("OS token type=%d elevation_type=%d elevated=%t enabled_admin=%t deny_only_admin=%t mode=%d", facts.TokenType, facts.ElevationType, facts.Elevated, facts.EnabledAdmin, facts.AdminDenyOnly, desktopTokenMode(facts))
	var impersonation windows.Token
	if err = windows.DuplicateTokenEx(process, windows.TOKEN_QUERY, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonation); err != nil {
		t.Fatal(err)
	}
	defer impersonation.Close()
	principal, err := tokenFacts(impersonation)
	if err != nil {
		t.Fatal(err)
	}
	binding.ServiceInstance = "native-token-readonly"
	if err = authorize(principal, binding, "S-1-5-18", binding.ServiceInstance); err != nil {
		t.Fatal(err)
	}
}
