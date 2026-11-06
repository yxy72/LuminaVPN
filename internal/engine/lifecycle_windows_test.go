//go:build windows

package engine

import (
	"net/netip"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"os"
	"strings"
	"testing"
	"unsafe"
)

func TestDesktopBaseAndStableResolverIdentity(t *testing.T) {
	data, err := os.ReadFile("../../examples/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	intent := policy.ChannelIntent{}
	s := State{Manifest: Manifest{Mode: Daily, Channels: &intent, Config: cfg, Binding: policy.Binding{Physical: "Wi-Fi", VPN: "NL-VPN-test", TUN: "NL-TUN-test", ControllerPort: 19091}}}
	var proxyPool, directPool netip.Prefix
	for _, direct := range []bool{false, true} {
		c, err := desktopConfig(s, nil, strings.Repeat("s", 32), nil, direct)
		if err != nil {
			t.Fatal(err)
		}
		tun := c["tun"].(map[string]any)
		if tun["enable"] != true || tun["auto-route"] != false {
			t.Fatal("dual off removed the owned base TUN")
		}
		for _, raw := range c["proxies"].([]any) {
			if p, ok := raw.(map[string]any); ok && p["name"] == "CORP-BOUND" {
				t.Fatal("dual off configured company ingress")
			}
		}
		dns := c["dns"].(map[string]any)
		if dns["fake-ip-ttl"] != 1 || dns["enable"] != true {
			t.Fatal("desktop resolver did not retain its explicit fake-IP lifetime")
		}
		if dns["nameserver-policy"].(map[string]any)[cfg.Company.Domains[0]].([]string)[0] != "rcode://refused" {
			t.Fatal("dual off allowed company DNS fallback")
		}
		pool := netip.MustParsePrefix(dns["fake-ip-range"].(string)).Masked()
		if direct {
			directPool = pool
		} else {
			proxyPool = pool
		}
	}
	if proxyPool != directPool || proxyPool != netip.MustParsePrefix("198.19.0.0/16") {
		t.Fatal("channel transition replaced the stable fake-IP allocation domain")
	}
	if intent != (policy.ChannelIntent{}) {
		t.Fatal("runtime compiler changed the immutable initial channel intent")
	}
	intent = policy.DefaultIntent()
	nodes := []policy.Node{{"type": "vless", "server": "203.0.113.7", "port": 443, "uuid": "11111111-1111-1111-1111-111111111111", "tls": true}}
	c, err := desktopConfig(s, nodes, strings.Repeat("s", 32), &companyRuntime{}, false)
	if err != nil {
		t.Fatal("company-local outage prevented the personal base config", err)
	}
	personalPresent := false
	for _, raw := range c["proxies"].([]any) {
		switch p := raw.(type) {
		case policy.Node:
			personalPresent = true
		case map[string]any:
			if p["name"] == "CORP-BOUND" {
				t.Fatal("unavailable company ingress left a usable company proxy")
			}
		}
	}
	if !personalPresent || c["dns"].(map[string]any)["nameserver-policy"].(map[string]any)[cfg.Company.Domains[0]].([]string)[0] != "rcode://refused" {
		t.Fatal("company outage escaped its own channel")
	}
}

func TestDesktopEnvironmentChangesPolicyWithoutReplacingFakeIPNamespace(t *testing.T) {
	data, err := os.ReadFile("../../examples/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	cfg.OfficeOverrides = []policy.Override{{Type: "domain", Value: "transition.example", Target: "personal"}}
	cfg.HomeOverrides = []policy.Override{{Type: "domain", Value: "transition.example", Target: "direct"}}
	nodes := []policy.Node{{"type": "vless", "server": "203.0.113.7", "port": 443, "uuid": "11111111-1111-1111-1111-111111111111", "tls": true}}
	for _, environment := range []string{"office", "home", "office"} {
		for _, direct := range []bool{false, true} {
			intent := policy.ChannelIntent{Personal: true, Environment: environment}
			s := State{Manifest: Manifest{Mode: Daily, Config: cfg, Channels: &intent, Binding: policy.Binding{Physical: "WLAN", VPN: "NL-VPN-test", TUN: "NL-TUN-test", ControllerPort: 19091}}}
			config, err := desktopConfig(s, nodes, strings.Repeat("s", 32), nil, direct)
			if err != nil {
				t.Fatal(err)
			}
			dns := config["dns"].(map[string]any)
			if netip.MustParsePrefix(dns["fake-ip-range"].(string)).Masked() != netip.MustParsePrefix("198.19.0.0/16") || dns["fake-ip-ttl"] != 1 || dns["enable"] != true {
				t.Fatal("environment/fallback transition replaced the fake-IP namespace")
			}
			group := "PHYSICAL"
			if environment == "office" && !direct {
				group = "PERSONAL"
			}
			for _, server := range dns["nameserver-policy"].(map[string]any)["transition.example"].([]string) {
				if !strings.HasSuffix(server, "#"+group) {
					t.Fatal("DNS did not follow the current environment/fallback policy", environment, direct, server)
				}
			}
			trafficGroup := "PHYSICAL"
			if environment == "office" {
				trafficGroup = "PERSONAL"
			}
			if !strings.Contains(strings.Join(config["rules"].([]string), "\n"), "DOMAIN,transition.example,"+trafficGroup) {
				t.Fatal("traffic did not follow the same environment/fallback policy", environment, direct)
			}
			if direct && environment == "office" {
				// The rule keeps its PERSONAL identity; the reload barrier opens
				// that selector to PHYSICAL only after the resolver is installed.
				for _, raw := range config["proxy-groups"].([]any) {
					entry := raw.(map[string]any)
					if entry["name"] == "PERSONAL" && strings.Join(entry["proxies"].([]string), ",") != "REJECT,PHYSICAL" {
						t.Fatal("direct fallback did not offer the physical selector")
					}
				}
			}
		}
	}
}

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
