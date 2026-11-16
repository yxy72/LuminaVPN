//go:build darwin

package engine

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"netlaunch/internal/policy"
	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/securefile"
	"netlaunch/internal/selector"
	"netlaunch/internal/testutil"
)

func TestDarwinDisabledChannelsDoNotReadCredentialsOrNodes(t *testing.T) {
	run := testutil.PrivateTempDir(t)
	intent := policy.ChannelIntent{}
	m := Manifest{Mode: Daily, Channels: &intent, Created: time.Now()}
	nodes, session, err := darwinChannelInputs(run, m)
	if err != nil || len(nodes) != 0 || session.Cookie != "" {
		t.Fatal("a disabled channel opened its input", err)
	}
	intent.Company = true
	if _, _, err := darwinChannelInputs(run, m); !errors.Is(err, errVPNAuthenticationRequired) {
		t.Fatalf("company start without credentials = %v", err)
	}
	intent.Company, intent.Personal = false, true
	if _, _, err := darwinChannelInputs(run, m); err == nil || errors.Is(err, errVPNAuthenticationRequired) {
		t.Fatalf("personal-only startup requested company authentication: %v", err)
	}
}

func TestDarwinDisabledCompanyDoesNotClaimUnusedVPNInterface(t *testing.T) {
	intent := policy.ChannelIntent{}
	s := State{Manifest: Manifest{Mode: Daily, Channels: &intent, Binding: policy.Binding{VPN: "utun50", TUN: "utun51"}}}
	unused := map[string]bool{"utun50": true}
	if hasDarwinCandidateInterface(s, unused) {
		t.Fatal("a disabled channel claimed an unrelated interface")
	}
	s.Children = []Child{{Role: "vpn", PID: 1234}}
	if !hasDarwinCandidateInterface(s, unused) {
		t.Fatal("recorded VPN resources disappeared from recovery")
	}
	s.Children = nil
	s.Manifest.Mode, s.Manifest.Channels = "", nil
	if !hasDarwinCandidateInterface(s, unused) {
		t.Fatal("legacy company recovery changed behavior")
	}
}

func TestDarwinStartupConfigProtectsCompanyAndSelectsPersonalDirect(t *testing.T) {
	intent := policy.ChannelIntent{}
	m := Manifest{
		Mode: Daily, Channels: &intent, Created: time.Now(),
		Binding: policy.Binding{Physical: "en0", VPN: "utun50", TUN: "utun51", ControllerPort: 19091},
		Config: policy.Config{
			Version: 1, Ports: policy.Ports{Proxy: 17890, DNS: 53},
			Company:   policy.Channel{Domains: []string{"company.example"}, CIDRs: []string{"192.0.2.0/24"}},
			Personal:  policy.Channel{Domains: []string{"personal.example"}},
			DirectDNS: []string{"192.0.2.53"},
			Probes:    []policy.Probe{{URL: "https://direct.example/health", Channel: "direct"}},
		},
	}
	config, err := darwinCoreConfig(m, nil, strings.Repeat("s", 32), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules := config["rules"].([]string)
	for _, rule := range []string{"DOMAIN,company.example,REJECT", "IP-CIDR,192.0.2.0/24,REJECT,no-resolve", "DOMAIN,personal.example,PERSONAL", "MATCH,PHYSICAL"} {
		if !slices.Contains(rules, rule) {
			t.Fatalf("expected generated rule %q", rule)
		}
	}
	dns := config["dns"].(map[string]any)["nameserver-policy"].(map[string]any)
	if !slices.Equal(dns["company.example"].([]string), []string{"rcode://refused"}) ||
		!slices.Equal(dns["personal.example"].([]string), []string{"udp://192.0.2.53#PHYSICAL"}) {
		t.Fatal("disabled traffic DNS can reach the wrong channel")
	}
	groups := config["proxy-groups"].([]any)
	company := groups[0].(map[string]any)["proxies"].([]string)
	personal := groups[1].(map[string]any)["proxies"].([]string)
	if !slices.Equal(company, []string{selector.Reject}) ||
		!slices.Equal(personal, []string{selector.Reject, "PHYSICAL"}) || config["listeners"] != nil {
		t.Fatal("disabled startup installed an unexpected egress or candidate listener")
	}
	t.Run("pinned core parses the actual startup configuration", func(t *testing.T) {
		root := os.Getenv("NETLAUNCH_TEST_RUNTIME")
		if root == "" {
			t.Skip("set NETLAUNCH_TEST_RUNTIME for the pinned core fixture")
		}
		if _, err := runtimebundle.Verify(root); err != nil {
			t.Fatal(err)
		}
		dir := testutil.PrivateTempDir(t)
		path := filepath.Join(dir, "core.json")
		if err := securefile.Write(path, config); err != nil {
			t.Fatal(err)
		}
		// Configuration-only inspection does not bind or change system DNS/TUN.
		cmd := exec.CommandContext(t.Context(), filepath.Join(root, "bin", "mihomo"), "-t", "-d", dir, "-f", path)
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if err := cmd.Run(); err != nil {
			t.Fatal("pinned core rejected macOS direct-only startup", err)
		}
	})
}

func TestDarwinIntentReadinessRequiresOnlyEnabledChannelsAndDirect(t *testing.T) {
	const scope = "system_tun"
	now := time.Now()
	for _, intent := range []policy.ChannelIntent{
		{}, {Company: true}, {Personal: true}, policy.DefaultIntent(),
	} {
		s := healthyState(now)
		s.Manifest.Mode, s.Manifest.Channels = Daily, &intent
		s.DesiredChannels, s.AppliedChannels = &intent, &intent
		s.TakeoverActive, s.ChannelGeneration, s.AppliedGeneration = true, 1, 1
		if !intent.Company {
			s.VPN = VPNSession{}
			s.Leases = nil
		}
		if !intent.Personal {
			s.Personal = "PHYSICAL"
		}
		for name, h := range s.Channels {
			h.ProbeScope = scope
			s.Channels[name] = h
		}
		if !intent.Company {
			delete(s.Channels, "company")
		}
		if !intent.Personal {
			delete(s.Channels, "personal")
		}
		desktopPhase(&s, now)
		if s.Phase != "ready" || !s.LastReady.Equal(now) {
			t.Fatalf("disabled channel blocked a complete proof: %+v %s", intent, s.Phase)
		}
		got := publicStatus(s, now)
		if !intent.Company && got.Channels["company"].Reason != "disabled_blocked" ||
			!intent.Personal && got.Channels["personal"].Reason != "disabled_direct" {
			t.Fatalf("disabled channel misreported: %+v %+v", intent, got.Channels)
		}
		probes := []policy.Probe{{Channel: "company"}, {Channel: "personal"}, {Channel: "direct"}}
		if expected := len(s.Channels); len(systemProbeTargets(probes, intent, s.Personal, true)) != expected {
			t.Fatalf("unexpected probe coverage: %+v", intent)
		}
		if intent.Company {
			s.VPN.Bootstrap = false
			desktopPhase(&s, now)
			if s.Phase == "ready" || slices.ContainsFunc(systemProbeTargets(probes, intent, s.Personal, false), func(p policy.Probe) bool { return p.Channel == "company" }) {
				t.Fatal("enabled but unauthorized company produced readiness or a probe")
			}
		}
		if !intent.Personal {
			s.Personal = selector.Reject
			desktopPhase(&s, now)
			if s.Phase == "ready" || channelView(s, "personal", now).Reason == "disabled_direct" {
				t.Fatal("personal direct was reported before its gate was applied")
			}
		}
		delete(s.Channels, "direct")
		desktopPhase(&s, now)
		if s.Phase == "ready" {
			t.Fatal("disabled evidence hid a missing direct proof")
		}
	}
}
