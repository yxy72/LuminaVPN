package app

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"netlaunch/internal/engine"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	p "netlaunch/internal/serviceprotocol"
	"netlaunch/internal/subscription"
	"netlaunch/internal/testutil"
)

func TestMacTypedCompanyStartRequiresAuthenticationBeforeStaging(t *testing.T) {
	profile := testutil.PrivateTempDir(t)
	cfg, err := policy.Decode([]byte(Example))
	if err != nil {
		t.Fatal(err)
	}
	intent := policy.ChannelIntent{Company: true}
	o := options{profile: profile, mode: engine.Daily, channels: &intent}
	if err := validateLaunchOptions(&o, "up"); err != nil {
		t.Fatal(err)
	}
	c := CLI{Out: io.Discard, Err: io.Discard}
	if err := c.upLockedContext(t.Context(), o, cfg, nil); !errors.Is(err, ErrMacAuthenticationRequired) {
		t.Fatalf("typed start without a session: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(profile, "runs")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unauthenticated start staged a run: %v", err)
	}
}

func TestMacCanceledStartPinsStopAfterNativeAuthorization(t *testing.T) {
	profile, first, second := macStopFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stop, err := bindRunStop(ctx, options{run: first})
	if err != nil {
		t.Fatal(err)
	}
	defer stop.Close()
	launch := func(ctx context.Context, action, run string) error {
		if action != "serve" || run != first {
			t.Fatalf("unexpected launch: %s %s", action, run)
		}
		setStopFixtureCurrent(t, profile, second)
		cancel()
		// Native authorization may return success as the app cancels.
		return nil
	}
	_, err = launchPreparedRun(ctx, stop, launch, func(string) (engine.Status, error) {
		t.Fatal("late native success should not begin polling readiness")
		return engine.Status{}, nil
	}, time.Second, time.Millisecond, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(first, "STOP")); err != nil {
		t.Fatalf("cancel did not publish STOP: %v", err)
	}
	requireNoStopMarker(t, second)
}

func TestMacUnsettledStartTimeoutRequestsIndependentStop(t *testing.T) {
	_, first, _ := macStopFixture(t)
	stop, err := bindRunStop(t.Context(), options{run: first})
	if err != nil {
		t.Fatal(err)
	}
	defer stop.Close()
	_, err = launchPreparedRun(t.Context(), stop, func(context.Context, string, string) error { return nil },
		func(string) (engine.Status, error) { return engine.Status{Phase: "starting"}, nil }, 20*time.Millisecond, time.Millisecond, nil)
	if err == nil {
		t.Fatal("an unresolved launch was reported ready")
	}
	if _, err := os.Stat(filepath.Join(first, "STOP")); err != nil {
		t.Fatalf("timed out launch did not publish STOP: %v", err)
	}
}

func TestMacSuccessfulStartLeavesRunActive(t *testing.T) {
	_, first, _ := macStopFixture(t)
	stop, err := bindRunStop(t.Context(), options{run: first})
	if err != nil {
		t.Fatal(err)
	}
	defer stop.Close()
	status, err := launchPreparedRun(t.Context(), stop, func(context.Context, string, string) error { return nil },
		func(string) (engine.Status, error) { return engine.Status{Phase: "ready"}, nil }, time.Second, time.Millisecond, nil)
	if err != nil || status.Phase != "ready" {
		t.Fatal(status.Phase, err)
	}
	requireNoStopMarker(t, first)
}

func TestMacStartupReportsRestoredFailureStage(t *testing.T) {
	_, run, _ := macStopFixture(t)
	stop, err := bindRunStop(t.Context(), options{run: run})
	if err != nil {
		t.Fatal(err)
	}
	defer stop.Close()
	intent := policy.ChannelIntent{Personal: true}
	_, err = launchPreparedRun(t.Context(), stop, func(context.Context, string, string) error { return nil },
		func(string) (engine.Status, error) {
			return engine.Status{Phase: "stopped", RecoveryReason: "startup_dns_port"}, nil
		}, time.Second, time.Millisecond, &intent)
	var failure *p.Error
	if !errors.As(err, &failure) || failure.Code != "MAC_START_DNS_PORT" {
		t.Fatalf("startup phase lost after restoration: %v", err)
	}
	requireNoStopMarker(t, run)
	if got := diagnosticProjection(engine.Status{RecoveryReason: "startup_dns_port"}, time.Now()); got.RecoveryReason != "startup_dns_port" {
		t.Fatal("diagnostic projection lost the startup stage")
	}
}

func TestMacStartupReadinessRequiresTheExactAppliedEnvironment(t *testing.T) {
	_, first, _ := macStopFixture(t)
	stop, err := bindRunStop(t.Context(), options{run: first})
	if err != nil {
		t.Fatal(err)
	}
	defer stop.Close()
	expected := policy.ChannelIntent{Personal: true, Environment: "office"}
	wrong := expected
	wrong.Environment = "home"
	calls := 0
	ready, err := launchPreparedRun(t.Context(), stop, func(context.Context, string, string) error { return nil },
		func(string) (engine.Status, error) {
			calls++
			s := engine.Status{Phase: "ready", Lifecycle: "running", TakeoverActive: true, DesiredChannels: &expected,
				AppliedChannels: &expected, ChannelGeneration: 1, AppliedGeneration: 1,
				Channels: map[string]engine.ChannelStatus{"direct": {State: "ready", PathState: "verified", ProbeScope: "system_tun", CheckedAt: time.Now()}},
			}
			switch calls {
			case 1:
				s.AppliedChannels = &wrong
			case 2:
				s.AppliedGeneration = 0
			}
			return s, nil
		}, time.Second, time.Millisecond, &expected)
	if err != nil || ready.Phase != "ready" || calls != 3 {
		t.Fatalf("startup used a wrong or unsettled environment report: phase=%s checks=%d err=%v", ready.Phase, calls, err)
	}
	requireNoStopMarker(t, first)
}

func TestMacManagedStartupWaitsForVerifiedBaseAndLeavesPersonalPending(t *testing.T) {
	_, run, _ := macStopFixture(t)
	stop, err := bindRunStop(t.Context(), options{run: run})
	if err != nil {
		t.Fatal(err)
	}
	defer stop.Close()
	intent := policy.ChannelIntent{Company: true, Personal: true}
	calls := 0
	observed, err := launchPreparedRun(t.Context(), stop, func(context.Context, string, string) error { return nil }, func(got string) (engine.Status, error) {
		if got != run {
			t.Fatal("startup read an unbound run")
		}
		calls++
		scope := engine.ChannelStatus{State: "ready", PathState: "verified", ProbeScope: "system_tun", CheckedAt: time.Now()}
		out := engine.Status{Phase: "managed", Lifecycle: "running", TakeoverActive: true,
			DesiredChannels: &intent, AppliedChannels: &intent, ChannelGeneration: 1, AppliedGeneration: 1,
			Personal: "REJECT", Channels: map[string]engine.ChannelStatus{
				"direct": scope, "company": scope, "personal": {State: "unknown", Reason: "probe_incomplete"},
			},
		}
		switch calls {
		case 1:
			delete(out.Channels, "company")
		case 2:
			scope.ProbeScope = "mixed_ingress"
			out.Channels["direct"] = scope
		case 3:
			scope.CheckedAt = scope.CheckedAt.Add(-3 * time.Minute)
			out.Channels["direct"] = scope
		}
		return out, nil
	}, time.Second, time.Millisecond, &intent)
	if err != nil || calls != 4 || observed.Phase != "managed" || observed.Personal != "REJECT" {
		t.Fatalf("unexpected proof or managed result: checks=%d phase=%s route=%s err=%v", calls, observed.Phase, observed.Personal, err)
	}
	if macStartupReportAccepted(observed, nil, time.Now()) {
		t.Fatal("legacy startup accepted a managed report")
	}
	requireNoStopMarker(t, run)
}

func TestMacLaunchEnvironmentSelectsExistingCoreTrafficAndResolverOverrides(t *testing.T) {
	profile := testutil.PrivateTempDir(t)
	cfg, err := policy.Decode([]byte(Example))
	if err != nil {
		t.Fatal(err)
	}
	domain := cfg.Personal.Domains[0]
	const homeDomain = "home-only.example"
	cfg.OfficeOverrides = []policy.Override{{Type: "domain", Value: domain, Target: "direct"}}
	cfg.HomeOverrides = []policy.Override{{Type: "domain", Value: homeDomain, Target: "personal"}}
	if err := securefile.Write(filepath.Join(profile, "policy.json"), cfg); err != nil {
		t.Fatal(err)
	}
	raw := []policy.Node{{"type": "vless", "server": "203.0.113.7", "port": 443, "uuid": "fixture-node", "tls": true}}
	if err := securefile.Write(filepath.Join(profile, "nodes.json"), raw); err != nil {
		t.Fatal(err)
	}
	binding := policy.Binding{Physical: "en0", VPN: "utun40", TUN: "utun41", ControllerPort: 19091}
	for _, test := range []struct{ env, target, route, resolver string }{
		{"", domain, "PERSONAL", "https://1.1.1.1/dns-query#PERSONAL"},
		{"office", domain, "PHYSICAL", "udp://223.5.5.5#PHYSICAL"},
		{"home", homeDomain, "PERSONAL", "https://1.1.1.1/dns-query#PERSONAL"},
	} {
		intent := policy.ChannelIntent{Personal: true, Environment: test.env}
		o := options{profile: profile, mode: engine.Daily, channels: &intent}
		selected, err := readLaunchPolicy(o)
		if err != nil {
			t.Fatal(err)
		}
		effective, nodes, err := effectiveLaunchProfile(o, selected)
		if err != nil {
			t.Fatal(err)
		}
		out, err := policy.CompileWithIntent(effective, nodes, binding, strings.Repeat("s", 32), launchIntent(o))
		if err != nil {
			t.Fatal(err)
		}
		resolver, _ := out["dns"].(map[string]any)["nameserver-policy"].(map[string]any)[test.target].([]string)
		rules := out["rules"].([]string)
		index := slices.IndexFunc(rules, func(rule string) bool { return strings.HasPrefix(rule, "DOMAIN,"+test.target+",") })
		if index < 0 || rules[index] != "DOMAIN,"+test.target+","+test.route || !slices.Equal(resolver, []string{test.resolver}) {
			t.Fatalf("incorrect core traffic or DNS for %q: %v %v", test.env, rules, resolver)
		}
		if test.env != "home" && slices.Contains(rules, "DOMAIN,"+homeDomain+",PERSONAL") {
			t.Fatal("Home override leaked into another environment")
		}
	}
}

func TestLateAuthReceiptCannotRecreateOrWriteIntoReplacedRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-request")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	identity, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+"-retired"); err != nil {
		t.Fatal(err)
	}
	if err := writeAuthReceipt(path, identity, "done"); err == nil {
		t.Fatal("late helper recreated a retired authentication request")
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeAuthReceipt(path, identity, "done"); err == nil {
		t.Fatal("late helper wrote an authentication receipt into a different request")
	}
}

func TestMacCompanyAuthUsesBoundPolicyWithoutPersonalConfiguration(t *testing.T) {
	profile := testutil.PrivateTempDir(t)
	request, err := securefile.TempDir(profile, macCompanyAuthPrefix)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Decode([]byte(Example))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Personal = policy.Channel{}
	cfg.Probes = []policy.Probe{cfg.Probes[0], cfg.Probes[3]}
	if err := securefile.Write(filepath.Join(profile, "policy.json"), cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := readPolicy(profile); err == nil {
		t.Fatal("test fixture must require company-only validation")
	}
	o := options{profile: profile, run: request}
	if _, err := readAuthenticationPolicy(o); err == nil {
		t.Fatal("a company-only request requires a bound endpoint")
	}
	if err := securefile.Write(filepath.Join(request, macCompanyAuthRequest), cfg.VPN); err != nil {
		t.Fatal(err)
	}
	verified, err := readAuthenticationPolicy(o)
	if err != nil || verified.VPN != cfg.VPN {
		t.Fatalf("a company-only profile should authorize its bound endpoint: %v", err)
	}
	cfg.VPN.EndpointIPv4 = "203.0.113.88"
	if err := securefile.Write(filepath.Join(profile, "policy.json"), cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := readAuthenticationPolicy(o); err == nil {
		t.Fatal("changed endpoint was accepted by an old authentication request")
	}
}

func TestMacOffStartupUsesOnlyAnExistingValidatedPersonalPool(t *testing.T) {
	profile := testutil.PrivateTempDir(t)
	cfg, err := policy.Decode([]byte(Example))
	if err != nil {
		t.Fatal(err)
	}
	intent := policy.ChannelIntent{}
	launch := options{profile: profile, mode: engine.Daily, channels: &intent}

	source := filepath.Join(profile, "fixture-source.yaml")
	yaml := []byte(`proxies: [{type: vless, server: 203.0.113.7, port: 443, uuid: fixture-node, tls: true}]
rules: ["DOMAIN,optional-route.example.net,DIRECT"]
`)
	if err := os.WriteFile(source, yaml, 0600); err != nil {
		t.Fatal(err)
	}
	sources := subscription.Sources{Nodes: subscription.Source{File: source, UseRules: true}, IntervalMinutes: 1}
	if err := securefile.Write(filepath.Join(profile, "sources.json"), sources); err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(profile, "subscription-cache.json")
	if got, nodes, err := effectiveLaunchProfile(launch, cfg); err != nil || len(nodes) != 0 || len(got.PersonalRules) != len(cfg.PersonalRules) {
		t.Fatal("off startup requires no Personal inventory or rules without a cache", err)
	}
	if _, err := os.Stat(cachePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("off startup fetched the configured source", err)
	}

	personal := intent
	personal.Personal = true
	if err := syncSubscriptionsForIntent(t.Context(), profile, cfg, personal, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	got, nodes, err := effectiveLaunchProfile(launch, cfg)
	if err != nil || len(nodes) != 1 || len(got.PersonalRules) != len(cfg.PersonalRules)+1 || intent.Personal {
		t.Fatal("off startup did not freeze the validated cached Personal policy and pool without enabling it", err)
	}
	staged := cfg
	staged.Company.CIDRs = []string{"203.0.113.7/32"}
	if got, nodes, err := effectiveLaunchProfile(launch, staged); err != nil || len(nodes) != 0 || len(got.PersonalRules) != len(staged.PersonalRules) {
		t.Fatal("off startup admitted an optional pool overlapping a restricted company prefix", err)
	}
}

func TestMacOffStartupCanFreezeManualNodes(t *testing.T) {
	profile := testutil.PrivateTempDir(t)
	cfg, err := policy.Decode([]byte(Example))
	if err != nil {
		t.Fatal(err)
	}
	raw := []policy.Node{{"type": "vless", "server": "203.0.113.7", "port": 443, "uuid": "fixture-node", "tls": true}}
	if err := securefile.Write(filepath.Join(profile, "nodes.json"), raw); err != nil {
		t.Fatal(err)
	}
	intent := policy.ChannelIntent{}
	launch := options{profile: profile, mode: engine.Validation, channels: &intent}
	if _, nodes, err := effectiveLaunchProfile(launch, cfg); err != nil || len(nodes) != 1 || nodes[0]["name"] != "P001" {
		t.Fatal("off startup did not freeze the sanitized manual pool", err)
	}

	cfg.Personal = policy.Channel{}
	cfg.Probes = []policy.Probe{cfg.Probes[0], cfg.Probes[3]}
	if _, nodes, err := effectiveLaunchProfile(launch, cfg); err != nil || len(nodes) != 0 {
		t.Fatal("off startup requires valid Personal targets only to freeze optional candidates", err)
	}
}
