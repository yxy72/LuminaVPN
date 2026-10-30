//go:build windows

package engine

import (
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"os"
	"strings"
	"testing"
	"unsafe"
)

func TestWindowsCoreUsesJournaledCaptureRoutes(t *testing.T) {
	data, e := os.ReadFile("../../examples/policy.json")
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := policy.Decode(data)
	if e != nil {
		t.Fatal(e)
	}
	s := State{Manifest: Manifest{Config: cfg, Binding: policy.Binding{Physical: "Wi-Fi", VPN: "NL-VPN-test", TUN: "NL-TUN-test", ControllerPort: 19091}}}
	company := &companyRuntime{proxy: map[string]any{"name": "CORP-BOUND", "type": "socks5", "server": "127.0.0.1", "port": 19443, "interface-name": "Loopback Pseudo-Interface 1"}}
	nodes := []policy.Node{{"type": "vless", "server": "203.0.113.7", "port": 443, "uuid": "11111111-1111-1111-1111-111111111111", "tls": true}}
	for _, enabled := range []bool{false, true} {
		c, e := configFor(s, nodes, strings.Repeat("s", 32), company, enabled)
		if e != nil {
			t.Fatal(e)
		}
		tun := c["tun"].(map[string]any)
		if tun["auto-route"] != false || tun["enable"] != enabled {
			t.Fatal("untracked core route takeover")
		}
		p := c["proxies"].([]any)[0].(map[string]any)
		if p["type"] != "socks5" || p["interface-name"] != "Loopback Pseudo-Interface 1" {
			t.Fatal("company bypassed authorized ingress")
		}
	}
}

func TestFrozenCoordinatorRequiresPublishedNativeIdentity(t *testing.T) {
	run := `C:\Users\tester\.netlaunch\runs\netlaunch-0123456789abcdef0123456789abcdef`
	me := platform.Identity{PID: 42, Birth: "native-creation-time", OwnerSID: "S-1-5-21-test", Executable: frozenSelf(run)}
	s := State{Runner: me, Manifest: Manifest{Executable: me.Executable}}
	if e := verifyFrozenRunner(run, s, me); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*platform.Identity){
		func(p *platform.Identity) { p.Executable = run + `\netlaunch.exe` },
		func(p *platform.Identity) { p.PID++ },
		func(p *platform.Identity) { p.Birth = "reused-pid" },
		func(p *platform.Identity) { p.OwnerSID = "another-user" },
	} {
		bad := me
		mutate(&bad)
		if verifyFrozenRunner(run, s, bad) == nil {
			t.Fatal("unpublished coordinator authorized")
		}
	}
}
func TestWindowsElevationABI(t *testing.T) {
	var info shellExecuteInfo
	if unsafe.Sizeof(info) != 112 || unsafe.Offsetof(info.Process) != 104 {
		t.Fatal("invalid Windows amd64 elevation ABI")
	}
}
