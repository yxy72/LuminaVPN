//go:build darwin

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"netlaunch/internal/companyproxy"
	"netlaunch/internal/dnswire"
	"netlaunch/internal/platform"
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
	physical := groups[2].(map[string]any)["proxies"].([]string)
	if !slices.Equal(company, []string{selector.Reject}) ||
		!slices.Equal(personal, []string{selector.Reject, "PHYSICAL"}) ||
		!slices.Equal(physical, []string{selector.Reject, "PHYSICAL-BOUND"}) || config["listeners"] != nil {
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

func TestDarwinRetainedCompanyUsesSameBlockedPolicyAcrossIntents(t *testing.T) {
	intent := policy.ChannelIntent{}
	m := Manifest{
		Mode: Daily, Channels: &intent,
		Binding: policy.Binding{Physical: "en0", VPN: "utun50", TUN: "utun51", ControllerPort: 19091},
		Config: policy.Config{
			Version: 1, Ports: policy.Ports{Proxy: 17890, DNS: 53},
			Company:   policy.Channel{Domains: []string{"company.example"}, CIDRs: []string{"192.0.2.0/24"}, DNS: []string{"192.0.2.53"}},
			Personal:  policy.Channel{Domains: []string{"personal.example"}},
			DirectDNS: []string{"198.51.100.53"},
			VPN:       policy.VPN{Server: "https://vpn.example", EndpointIPv4: "203.0.113.2"},
			Probes: []policy.Probe{
				{URL: "https://company.example/health", Channel: "company"},
				{URL: "https://direct.example/health", Channel: "direct"},
			},
		},
	}
	if !darwinCanRetainCompany(m, nil) {
		t.Fatal("complete frozen company policy was rejected")
	}
	proxy, err := companyproxy.Proxy("127.0.0.1:19876", companyproxy.Credentials{
		Username: "company", Password: "loopback-fixture-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy["interface-name"] = "lo0"
	company := &companyRuntime{proxy: proxy}
	secret := strings.Repeat("s", 32)
	off, err := darwinCoreConfig(m, nil, secret, company, nil)
	if err != nil {
		t.Fatal(err)
	}
	intent.Company = true
	on, err := darwinCoreConfig(m, nil, secret, company, nil)
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := json.Marshal(off)
	b2, _ := json.Marshal(on)
	if !bytes.Equal(b1, b2) {
		t.Fatal("company toggle would require changing the core configuration")
	}
	rules := off["rules"].([]string)
	for _, pair := range [][2]string{
		{"DOMAIN,company.example,CORP", "DOMAIN,company.example,REJECT"},
		{"IP-CIDR,192.0.2.0/24,CORP,no-resolve", "IP-CIDR,192.0.2.0/24,REJECT,no-resolve"},
	} {
		i := slices.Index(rules, pair[0])
		if i == -1 || i+1 >= len(rules) || rules[i+1] != pair[1] {
			t.Fatal("company target is missing its fail-closed guard")
		}
	}
	groups := off["proxy-groups"].([]any)
	if got := groups[0].(map[string]any)["proxies"].([]string); !slices.Equal(got, []string{selector.Reject, "CORP-BOUND"}) {
		t.Fatalf("unexpected company selector: %v", got)
	}
	dns := off["dns"].(map[string]any)["nameserver-policy"].(map[string]any)
	if !slices.Equal(dns["company.example"].([]string), []string{"tcp://192.0.2.53:53#CORP"}) ||
		!slices.Equal(dns["personal.example"].([]string), []string{"udp://198.51.100.53#PHYSICAL"}) {
		t.Fatal("company or personal DNS crossed the wrong selector")
	}
	t.Run("pinned core keeps blocked DNS off physical", func(t *testing.T) {
		checkDarwinCompanyDNSGate(t, off)
	})
	intent.Company = false
	m.Config.VPN = policy.VPN{}
	if darwinCanRetainCompany(m, nil) {
		t.Fatal("incomplete disabled policy reserved a live ingress")
	}
}

func checkDarwinCompanyDNSGate(t *testing.T, config map[string]any) {
	t.Helper()
	root := os.Getenv("NETLAUNCH_TEST_RUNTIME")
	if root == "" {
		t.Skip("set NETLAUNCH_TEST_RUNTIME for the pinned core fixture")
	}
	if _, err := runtimebundle.Verify(root); err != nil {
		t.Fatal(err)
	}
	watchConnections := func(hits *atomic.Int32) string {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		go func() {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				hits.Add(1)
				_ = conn.Close()
			}
		}()
		return l.Addr().String()
	}
	var physicalHits, companyHits, personalHits atomic.Int32
	physical := "tcp://" + watchConnections(&physicalHits)
	credentials := companyproxy.Credentials{
		Username: "company", Password: "loopback-fixture-password",
	}
	company, err := companyproxy.Proxy(watchConnections(&companyHits), credentials)
	if err != nil {
		t.Fatal(err)
	}
	company["interface-name"] = "lo0"
	config["proxies"].([]any)[0] = company
	personal, err := companyproxy.Proxy(watchConnections(&personalHits), credentials)
	if err != nil {
		t.Fatal(err)
	}
	personal["name"], personal["interface-name"] = "P-FIXTURE", "lo0"
	config["proxies"] = append(config["proxies"].([]any), personal)
	config["proxy-groups"].([]any)[1].(map[string]any)["proxies"] = []string{selector.Reject, "P-FIXTURE"}
	config["mixed-port"] = 0
	config["interface-name"] = "lo0"
	controllerPort, err := platform.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	dnsPort, err := platform.FreePort()
	if err != nil || dnsPort == controllerPort {
		t.Fatalf("fixture DNS port: %d, %v", dnsPort, err)
	}
	controller := net.JoinHostPort("127.0.0.1", strconv.Itoa(controllerPort))
	dnsAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsPort))
	config["external-controller"] = controller
	dns := config["dns"].(map[string]any)
	dns["listen"] = dnsAddress
	for _, key := range []string{"nameserver", "direct-nameserver", "default-nameserver", "proxy-server-nameserver"} {
		dns[key] = []string{physical}
	}
	dns["fake-ip-filter"] = []string{
		"closed.example", "open.example", "closed-again.example", "direct.example", "personal-first.example", "personal-last.example",
	}
	dns["nameserver-policy"] = map[string]any{
		"closed.example":         []string{physical + "#CORP"},
		"open.example":           []string{physical + "#CORP"},
		"closed-again.example":   []string{physical + "#CORP"},
		"personal-first.example": []string{physical + "#PERSONAL"},
		"personal-last.example":  []string{physical + "#PERSONAL"},
	}
	dir := testutil.PrivateTempDir(t)
	path := filepath.Join(dir, "core.json")
	if err := securefile.Write(path, config); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(root, "bin", "mihomo"), "-d", dir, "-f", path)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	request := func(ctx context.Context, method, path string, payload any) error {
		return coreRequest(ctx, controller, config["secret"].(string), method, path, payload, nil)
	}
	if err := waitReady(ctx, 4*time.Second, func() error { return nil }, func(c context.Context) error {
		return request(c, "GET", "/version", nil)
	}); err != nil {
		t.Fatal(err)
	}
	query := func(host string) {
		_, _ = dnswire.Query(ctx, func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", dnsAddress)
		}, "192.0.2.53", host)
	}
	set := func(group, node string) {
		t.Helper()
		if err := request(ctx, "PUT", "/proxies/"+group, map[string]string{"name": node}); err != nil {
			t.Fatal(err)
		}
	}
	set("PERSONAL", "P-FIXTURE")
	query("personal-first.example")
	if personalHits.Load() == 0 {
		t.Fatal("fixture did not observe personal DNS before company changes")
	}
	query("closed.example")
	if physicalHits.Load() != 0 || companyHits.Load() != 0 {
		t.Fatal("blocked company DNS escaped the core's closed gate")
	}
	set("CORP", "CORP-BOUND")
	query("open.example")
	if companyHits.Load() == 0 || physicalHits.Load() != 0 {
		t.Fatal("company DNS failed to use only the fixed ingress")
	}
	set("CORP", selector.Reject)
	atClosure := companyHits.Load()
	query("closed-again.example")
	if companyHits.Load() != atClosure || physicalHits.Load() != 0 {
		t.Fatal("company DNS escaped after the gate reclosed")
	}
	beforePersonal := personalHits.Load()
	query("personal-last.example")
	if personalHits.Load() <= beforePersonal || physicalHits.Load() != 0 {
		t.Fatal("closing company disrupted the selected personal resolver")
	}
	query("direct.example")
	if physicalHits.Load() == 0 {
		t.Fatal("fixture did not observe the physical resolver")
	}
}
