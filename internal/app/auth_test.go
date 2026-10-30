package app

import (
	"bytes"
	"netlaunch/internal/auth"
	"netlaunch/internal/policy"
	"netlaunch/internal/testutil"
	"path/filepath"
	"strings"
	"testing"
)

func TestCachedAuthNeedsNoConsoleOrRuntime(t *testing.T) {
	if !authenticationSupported() {
		t.Skip("native authentication unsupported")
	}
	profile := testutil.PrivateTempDir(t)
	vpn := policy.VPN{Server: "https://vpn.example.com:4433", EndpointIPv4: "192.0.2.1"}
	s, e := auth.Parse("COOKIE='fixture-only'\nHOST='vpn.example.com'\nCONNECT_URL='https://vpn.example.com:4433/'\nFINGERPRINT='sha256:abc123'\nRESOLVE='vpn.example.com:192.0.2.1'\n", vpn)
	if e != nil {
		t.Fatal(e)
	}
	if e = auth.Save(profile, vpn, s); e != nil {
		t.Fatal(e)
	}
	var output bytes.Buffer
	c := CLI{Out: &output}
	if e = c.obtainAuth(options{profile: profile, runtime: filepath.Join(profile, "intentionally-missing-runtime")}, policy.Config{VPN: vpn}); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(output.String(), "Reusing") || strings.Contains(output.String(), "fixture-only") {
		t.Fatal("cache reuse output")
	}
}
