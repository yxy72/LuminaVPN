//go:build darwin

package platform

import (
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestNativeRouteFixtures(t *testing.T) {
	rows := ParseRoutes("Routing tables\nDestination Gateway Flags Netif Expire\ndefault 192.0.2.254 UGScg en4\n10.7.8 link#33 UCS utun33\n10.7.8.9 utun33 UHIS utun33\n192.0.2.1 192.0.2.254 UGHS en4\n198.18/15 utun34 US utun34\n")
	if len(rows) != 4 {
		t.Fatal(rows)
	}
	if rows[0].Prefix != "10.7.8.0/24" || !rows[1].Scoped || rows[3].Prefix != "198.18.0.0/15" {
		t.Fatal(rows)
	}
	a, e := RouteArgs("add", rows[1])
	if e != nil {
		t.Fatal(e)
	}
	want := []string{"-n", "add", "-host", "-ifscope", "utun33", "10.7.8.9", "-interface", "utun33"}
	if !reflect.DeepEqual(a, want) {
		t.Fatal(a)
	}
	r := rows[2]
	r.Prefix = "0.0.0.0/0"
	if _, e = RouteArgs("add", r); e == nil {
		t.Fatal("default route authorized")
	}
}
func TestConflictFixtures(t *testing.T) {
	if !EnabledProxy("<dictionary> {\n HTTPEnable : 1\n}") {
		t.Fatal("missed proxy")
	}
	if EnabledProxy("HTTPEnable : 0\nHTTPSEnable : 0") {
		t.Fatal("false conflict")
	}
	if !HasTunnelDefault("0/1 utun5 USc utun5\n") {
		t.Fatal("missed split default")
	}
	if HasTunnelDefault("default 192.0.2.254 UGScg en4\n") {
		t.Fatal("physical default rejected")
	}
}

func TestProcessIdentityHasFullExecutable(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "5")
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Signal(os.Interrupt); cmd.Wait() }()
	p, e := Process(cmd.Process.Pid)
	if e != nil || p.PID != cmd.Process.Pid || p.Executable != "/bin/sleep" || p.Command != "/bin/sleep 5" || strings.TrimSpace(p.Birth) == "" {
		t.Fatal(p, e)
	}
}
