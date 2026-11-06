//go:build windows

package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"netlaunch/internal/policy"
)

func TestDesktopStableCompanyGateNeverChangesPersonalCoreConfiguration(t *testing.T) {
	raw, err := os.ReadFile("../../examples/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	proxy := map[string]any{"name": "CORP-BOUND", "type": "socks5", "server": "127.0.0.1", "port": 55001, "username": "company", "password": "fixture-nonce", "interface-name": "Loopback"}
	company := &companyRuntime{proxy: proxy}
	var initial []byte
	for _, enabled := range []bool{false, true, false, true} {
		intent := policy.ChannelIntent{Company: enabled}
		s := State{Manifest: Manifest{Mode: Daily, Config: cfg, Channels: &intent, Binding: policy.Binding{Physical: "WLAN", VPN: "NL-VPN-test", TUN: "NL-TUN-test", ControllerPort: 19091}}}
		config, err := desktopConfig(s, nil, strings.Repeat("s", 32), company, true)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		if initial == nil {
			initial = encoded
		} else if !bytes.Equal(initial, encoded) {
			t.Fatal("company-only change required a core/fake-IP allocator reload")
		}
		group := config["proxy-groups"].([]any)[0].(map[string]any)
		if group["name"] != "CORP" || group["proxies"].([]string)[0] != "REJECT" {
			t.Fatal("stable company ingress was not closed by default")
		}
		if intent.Company != enabled {
			t.Fatal("compiler mutated explicit desired company state")
		}
	}
	// An incomplete disabled company configuration must never turn an empty
	// DNS policy into permission to consult the physical/default resolver.
	cfg.Company.DNS = nil
	intent := policy.ChannelIntent{}
	s := State{Manifest: Manifest{Config: cfg, Channels: &intent, Binding: policy.Binding{Physical: "WLAN", VPN: "NL-VPN-test", TUN: "NL-TUN-test", ControllerPort: 19091}}}
	config, err := desktopConfig(s, nil, strings.Repeat("s", 32), company, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range cfg.Company.Domains {
		servers := config["dns"].(map[string]any)["nameserver-policy"].(map[string]any)[domain].([]string)
		if len(servers) != 1 || servers[0] != "rcode://refused" {
			t.Fatal("missing company DNS escaped its closed channel")
		}
	}
}

func TestDesktopCompanyTerminalFailurePreservesReadyPersonalBase(t *testing.T) {
	for _, reason := range []string{"certificate_rejected", "runtime_load_failed"} {
		retry := &vpnRetry{}
		personal := ChannelHealth{ChannelStatus: ChannelStatus{State: "ready", PathState: "verified", ProbeScope: "system_tun", CheckedAt: time.Now()}}
		state := State{TakeoverActive: true, Personal: "P001", Channels: map[string]ChannelHealth{"personal": personal}}
		cleanups := 0
		terminal, err := desktopVPNFailure(retry, time.Now(), Child{PID: 42, Birth: "fixture-birth"}, reason, func() error { cleanups++; return nil })
		if err != nil || terminal != reason || cleanups != 1 {
			t.Fatal("company failure tore down the personal base", reason, err)
		}
		markDesktopCompanyTerminal(&state, terminal, time.Now())
		if !state.TakeoverActive || state.Personal != "P001" || !reflect.DeepEqual(state.Channels["personal"], personal) || state.Channels["company"].State != "blocked" || state.Channels["company"].Reason != reason {
			t.Fatal("company failure changed ready personal evidence or removed the base")
		}
		if retry.Due(time.Now().Add(time.Hour)) {
			t.Fatal("terminal company failure entered an automatic retry loop")
		}
	}
	for _, reason := range []string{"exit_observation_failed", "tun_failed", "permission_denied", "unknown"} {
		if _, err := desktopVPNFailure(&vpnRetry{}, time.Now(), Child{PID: 42, Birth: "fixture"}, reason, func() error {
			t.Fatal("ownership/unknown failure was treated as a local transport failure")
			return nil
		}); err == nil {
			t.Fatal("ownership failure did not request global recovery")
		}
	}
	cleanupError := errors.New("exact company recovery unknown")
	if _, err := desktopVPNFailure(&vpnRetry{}, time.Now(), Child{PID: 42, Birth: "fixture"}, "certificate_rejected", func() error { return cleanupError }); !errors.Is(err, cleanupError) {
		t.Fatal("strict cleanup failure was suppressed")
	}
}

func TestDesktopCompanyOldServerCannotInterruptReusedListener(t *testing.T) {
	i := &desktopCompanyIngress{generation: 2}
	interrupts := 0
	interrupt := func() error { interrupts++; return nil }
	if err := i.interruptLease(1, interrupt); err != nil || interrupts != 0 {
		t.Fatal("late old server close interrupted the new listener lease")
	}
	if err := i.interruptLease(2, interrupt); err != nil || interrupts != 1 {
		t.Fatal("current listener lease could not stop its own accept")
	}
}
