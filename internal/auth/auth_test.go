package auth

import (
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/testutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var vpn = policy.VPN{Server: "https://vpn.example.com:4433", EndpointIPv4: "192.0.2.1"}

func output(host string) string {
	return "COOKIE='test-session'\nHOST='" + host + "'\nCONNECT_URL='https://vpn.example.com:4433/'\nFINGERPRINT='sha256:abc123'\nRESOLVE='vpn.example.com:192.0.2.1'\n"
}
func TestAuthParser(t *testing.T) {
	for _, host := range []string{"vpn.example.com", "192.0.2.1"} {
		if _, e := Parse(output(host), vpn); e != nil {
			t.Fatal(e)
		}
	}
	for _, bad := range []string{output("192.0.2.2"), output("evil.example.com"), output("vpn.example.com") + "COOKIE='again'\n", strings.Replace(output("192.0.2.1"), "RESOLVE=", "INVALID=", 1), strings.Replace(output("vpn.example.com"), "COOKIE='test-session'", "COOKIE=$(run)", 1), strings.ReplaceAll(output("vpn.example.com"), ":4433/", ":4434/")} {
		if _, e := Parse(bad, vpn); e == nil {
			t.Fatal("unsafe auth accepted")
		}
	}
}
func TestPrivateCacheAndExpiry(t *testing.T) {
	dir := testutil.PrivateTempDir(t)
	os.Chmod(dir, 0700)
	s, e := Parse(output("vpn.example.com"), vpn)
	if e != nil {
		t.Fatal(e)
	}
	if e = Save(dir, vpn, s); e != nil {
		t.Fatal(e)
	}
	if _, ok := Load(dir, vpn); !ok {
		t.Fatal("cache not reusable")
	}
	if _, e := securefile.Read(filepath.Join(dir, "session.json"), 65536, true); e != nil {
		t.Fatal("cache permissions", e)
	}
	changed := vpn
	changed.EndpointIPv4 = "192.0.2.2"
	if _, ok := Load(dir, changed); ok {
		t.Fatal("session moved across endpoint")
	}
	s.Created = time.Now().Add(-MaxAge - time.Second)
	Save(dir, vpn, s)
	if _, ok := Load(dir, vpn); ok {
		t.Fatal("expired session reused")
	}
	if _, e = os.Stat(filepath.Join(dir, "session.json")); !os.IsNotExist(e) {
		t.Fatal("expired cache retained")
	}
	s.Created = time.Now()
	Save(dir, vpn, s)
	testutil.MakePublic(t, filepath.Join(dir, "session.json"))
	if _, ok := Load(dir, vpn); ok {
		t.Fatal("public cache used")
	}
}
