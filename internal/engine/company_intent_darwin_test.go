//go:build darwin

package engine

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"netlaunch/internal/auth"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
)

func companyTransitionFixture(t *testing.T, enabled bool) State {
	t.Helper()
	intent := policy.ChannelIntent{Company: enabled, Personal: true, Environment: "home"}
	cfg := policy.Config{
		Version: 1, Ports: policy.Ports{Proxy: 17890, DNS: 53},
		Company:   policy.Channel{Domains: []string{"company.example"}, DNS: []string{"192.0.2.53"}},
		Personal:  policy.Channel{Domains: []string{"personal.example"}, DNS: []string{"https://198.51.100.54/dns-query"}},
		DirectDNS: []string{"198.51.100.53"},
		VPN:       policy.VPN{Server: "https://vpn.example", EndpointIPv4: "203.0.113.2"},
		Probes: []policy.Probe{
			{URL: "https://company.example/health", Channel: "company"},
			{URL: "https://personal.example/health", Channel: "personal"},
			{URL: "https://direct.example/health", Channel: "direct"},
		},
	}
	return State{
		Manifest: Manifest{Mode: Daily, Config: cfg, Channels: &intent},
		Runner:   platform.Identity{PID: 200, Birth: "runner"}, RunSpecDigest: "frozen-run",
		DesiredChannels: &intent, AppliedChannels: &intent, ChannelGeneration: 1, AppliedGeneration: 1,
		TakeoverActive: true, DarwinCompany: &darwinCompanyControl{}, Phase: "managed",
		Channels: map[string]ChannelHealth{"personal": {Node: "P001"}},
		Personal: "P001",
	}
}

func TestDarwinCompanyOffRevokesOnlyCompanyAndPublishesAfterCleanup(t *testing.T) {
	s := companyTransitionFixture(t, true)
	s.VPN.Bootstrap = true
	s.Children = []Child{{Role: "vpn", PID: 201, Released: true}}
	s.Routes = []OwnedRoute{
		{Route: platform.Route{Prefix: "203.0.113.2/32"}, State: "applied"},
		{Route: platform.Route{Prefix: "192.0.2.53/32", Scoped: true}, State: "applied"},
		{Route: platform.Route{Prefix: "203.0.113.3/32"}, State: "applied"},
	}
	personal := s.Channels["personal"]
	if err := queueDarwinCompanyChange(&s, "off", 1, false); err != nil {
		t.Fatal(err)
	}
	if !currentIntent(s).Company || !s.VPN.Bootstrap {
		t.Fatal("admission mutated a coordinator operation")
	}
	if err := queueDarwinCompanyChange(&s, "off", 1, false); err != nil {
		t.Fatal("exact retry was not idempotent", err)
	}
	if queueDarwinCompanyChange(&s, "off", 1, true) == nil || queueDarwinCompanyChange(&s, "second", 1, false) == nil {
		t.Fatal("a pending command accepted conflicting input")
	}
	if err := beginDarwinCompanyChange(&s); err != nil {
		t.Fatal(err)
	}
	if s.VPN.Bootstrap || !s.Children[0].DarwinVPNRetired {
		t.Fatal("an old VPN attempt retained authority after applying OFF")
	}
	change, err := pendingDarwinCompanyChange(s)
	if err != nil {
		t.Fatal(err)
	}
	gateClosed := false
	err = change.apply(func() error {
		t.Fatal("OFF took the enable path")
		return nil
	}, func() error {
		return fenceDarwinCompanyTraffic(&s, func() error { return nil }, func() error {
			gateClosed = true
			return retireDarwinCompanyRoutes(&s, func(index int) error {
				s.Routes[index].State = "removed"
				return nil
			})
		})
	}, func() error {
		if !gateClosed || s.Routes[0].State != "removed" || s.Routes[1].State != "removed" || s.Routes[2].State != "applied" {
			t.Fatal("applied published before exact company route cleanup")
		}
		return change.confirm(&s)
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.AppliedChannels.Company || !s.AppliedChannels.Personal || s.AppliedChannels.Environment != "home" ||
		s.AppliedGeneration != 2 || s.Personal != "P001" || !reflect.DeepEqual(s.Channels["personal"], personal) {
		t.Fatal("transition altered the personal route, policy, or health")
	}
	if queueDarwinCompanyChange(&s, "stale", 1, true) == nil {
		t.Fatal("stale generation admitted after OFF")
	}
}

func TestDarwinCompanyOnRequiresReadbackAndExactRun(t *testing.T) {
	s := companyTransitionFixture(t, false)
	if err := queueDarwinCompanyChange(&s, "on", 1, true); err != nil {
		t.Fatal(err)
	}
	if err := beginDarwinCompanyChange(&s); err != nil {
		t.Fatal(err)
	}
	change, err := pendingDarwinCompanyChange(s)
	if err != nil {
		t.Fatal(err)
	}
	s.RunSpecDigest = "replacement"
	if change.confirm(&s) == nil {
		t.Fatal("confirmation accepted a replacement run")
	}
	s.RunSpecDigest = "frozen-run"
	gateFailure := errors.New("closed gate was not verified")
	stop := func() error {
		t.Fatal("ON took the stop VPN path")
		return nil
	}
	if err := change.apply(func() error { return gateFailure }, stop, func() error {
		t.Fatal("ON published after missing REJECT readback")
		return nil
	}); !errors.Is(err, gateFailure) {
		t.Fatal(err)
	}
	if !s.DarwinCompany.Pending || s.AppliedGeneration != 1 {
		t.Fatal("failed transition advanced the revision")
	}
	if err := change.apply(func() error { return nil }, stop, func() error { return change.confirm(&s) }); err != nil {
		t.Fatal(err)
	}
	if !s.AppliedChannels.Company || s.VPN.Bootstrap || s.AppliedGeneration != 2 {
		t.Fatal("applying ON policy authorized the company path")
	}
	s.Manifest.ValidationTimeout, s.Manifest.Created = time.Second, time.Now().Add(-time.Minute)
	if err := checkDarwinCompanyOwner(t.TempDir(), s); !errors.Is(err, errDarwinValidationExpired) {
		t.Fatalf("expired transition passed the native guard: %v", err)
	}
}

func TestDarwinCompanyRefreshRequiresAppliedGenerationAndFrozenEndpoint(t *testing.T) {
	s := companyTransitionFixture(t, true)
	now := time.Now()
	vpn := s.Manifest.Config.VPN
	session := auth.Session{Cookie: "fixture", Host: "vpn.example", Fingerprint: "sha256:fixture", Created: now}
	encode := func(generation uint64, endpoint policy.VPN, session auth.Session) []byte {
		raw, err := json.Marshal(map[string]any{"generation": generation, "vpn": endpoint, "session": session})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	valid := encode(1, vpn, session)
	if got, present, err := decodeDarwinCompanyRefresh(valid, s, now); err != nil || !present || got.Cookie != session.Cookie {
		t.Fatal("valid scoped refresh rejected", present, err)
	}
	otherEndpoint := vpn
	otherEndpoint.EndpointIPv4 = "203.0.113.3"
	expired := session
	expired.Created = now.Add(-3 * time.Hour)
	for _, raw := range [][]byte{encode(2, vpn, session), encode(1, otherEndpoint, session), encode(1, vpn, expired)} {
		if _, present, err := decodeDarwinCompanyRefresh(raw, s, now); err != nil || present {
			t.Fatal("unusable managed refresh affected the running channel", present, err)
		}
	}
	if err := queueDarwinCompanyChange(&s, "off", 1, false); err != nil {
		t.Fatal(err)
	}
	if _, present, err := decodeDarwinCompanyRefresh(valid, s, now); err != nil || present {
		t.Fatal("pending OFF accepted a late refresh", present, err)
	}
}
