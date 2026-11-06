package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStorageFirstUseIsDistinctFromRunningIntent(t *testing.T) {
	c := Config{Version: 1, Ports: Ports{Proxy: 17890, DNS: 17891}}
	if err := c.ValidateForStorage(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeForStorage(raw); err != nil {
		t.Fatal(err)
	}
	plan, err := RulePlanForStorage(c)
	if err != nil {
		t.Fatal(err)
	}
	explanation, err := Explain(plan, "unconfigured.example")
	if err != nil || explanation.Winner.Target != "direct" || !explanation.StaticOnly {
		t.Fatal("saved first-use plan did not remain a static explanation", explanation, err)
	}
	if _, err = RulePlan(c); err == nil {
		t.Fatal("saved plan weakened legacy runtime validation")
	}
	if c.ValidateForIntent(ChannelIntent{}) == nil {
		t.Fatal("storage validation weakened the running base prerequisites")
	}
	if _, err = DecodeForIntent(raw, ChannelIntent{}); err == nil {
		t.Fatal("running decode accepted an incomplete stored profile")
	}
	c.DirectDNS = []string{"1.1.1.1"}
	if c.ValidateForIntent(ChannelIntent{}) == nil {
		t.Fatal("running decode no longer requires a direct probe")
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.DirectDNS = []string{"not-an-address"} },
		func(c *Config) { c.Company.Domains = []string{"*.invalid.example"} },
		func(c *Config) { c.Personal.DNS = []string{"http://1.1.1.1/dns-query"} },
		func(c *Config) { c.VPN.Server = "http://vpn.example" },
		func(c *Config) { c.Probes = []Probe{{URL: "http://probe.example", Channel: "direct"}} },
		func(c *Config) {
			c.OfficeOverrides = []Override{{Type: "domain", Value: "*.invalid.example", Target: "direct"}}
		},
	} {
		bad := Config{Version: 1, Ports: Ports{Proxy: 17890, DNS: 17891}}
		mutate(&bad)
		if bad.ValidateForStorage() == nil {
			t.Fatalf("storage accepted malformed supplied profile: %+v", bad)
		}
		raw, err := json.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = DecodeForStorage(raw); err == nil {
			t.Fatal("storage decode accepted malformed supplied data")
		}
	}
	if _, err = DecodeForStorage(append(raw, []byte(` {}`)...)); err == nil {
		t.Fatal("storage decode accepted multiple JSON values")
	}
	if _, err = DecodeForStorage([]byte(`{"version":1,"ports":{"proxy":17890,"dns":17891},"unknown":true}`)); err == nil {
		t.Fatal("storage decode accepted an unknown field")
	}
}

func TestDisabledChannelsAllowUnconfiguredProfiles(t *testing.T) {
	c := fixture(t)
	c.Company = Channel{}
	c.Personal = Channel{}
	c.VPN = VPN{}
	var probes []Probe
	for _, p := range c.Probes {
		if p.Channel == "direct" {
			probes = append(probes, p)
		}
	}
	c.Probes = probes
	if e := c.ValidateForIntent(ChannelIntent{}); e != nil {
		t.Fatal(e)
	}
	if c.Validate() == nil {
		t.Fatal("legacy dual-enabled validation was weakened")
	}
	if _, e := CompileWithIntent(c, nil, Binding{"Ethernet", "NL-VPN", "NL-TUN", 19091}, strings.Repeat("s", 32), ChannelIntent{}); e != nil {
		t.Fatal(e)
	}
	c.Company.Domains = []string{"*.invalid.example"}
	if c.ValidateForIntent(ChannelIntent{}) == nil {
		t.Fatal("disabled malformed target accepted")
	}
}
func TestCompanyDisabledIsExactRejectWithoutCompanyDNS(t *testing.T) {
	c := fixture(t)
	c.VPN = VPN{}
	c.Company.DNS = nil
	out, e := CompileWithIntent(c, nodes(), Binding{"Ethernet", "NL-VPN", "NL-TUN", 19091}, strings.Repeat("s", 32), ChannelIntent{Personal: true})
	if e != nil {
		t.Fatal(e)
	}
	for _, raw := range out["proxies"].([]any) {
		var name any
		switch proxy := raw.(type) {
		case map[string]any:
			name = proxy["name"]
		case Node:
			name = proxy["name"]
		}
		if name == "CORP-BOUND" {
			t.Fatal("disabled company proxy exists")
		}
	}
	plan, e := RulePlanForIntent(c, ChannelIntent{Personal: true})
	if e != nil {
		t.Fatal(e)
	}
	ex, _ := Explain(plan, c.Company.Domains[0])
	if ex.Winner.Target != "reject" {
		t.Fatal(ex)
	}
	dns := out["dns"].(map[string]any)["nameserver-policy"].(map[string]any)
	if dns[c.Company.Domains[0]].([]string)[0] != "rcode://refused" {
		t.Fatal(dns)
	}
}
func TestEnvironmentOverridesTrafficAndDNSButNeverCompany(t *testing.T) {
	c := fixture(t)
	domain := c.Personal.Domains[0]
	suffix := domain[strings.IndexByte(domain, '.')+1:]
	c.OfficeOverrides = []Override{{"domain_suffix", suffix, "direct"}, {"domain", c.Company.Domains[0], "direct"}}
	c.HomeOverrides = []Override{{"domain", domain, "personal"}}
	for _, env := range []string{"office", "home"} {
		intent := ChannelIntent{Company: true, Personal: true, Environment: env}
		plan, e := RulePlanForIntent(c, intent)
		if e != nil {
			t.Fatal(e)
		}
		ex, _ := Explain(plan, domain)
		want := "personal"
		if env == "office" {
			want = "direct"
		}
		if ex.Winner.Target != want {
			t.Fatal(env, ex)
		}
		corp, _ := Explain(plan, c.Company.Domains[0])
		if corp.Winner.Target != "company" {
			t.Fatal("override bypassed company", corp)
		}
		out, e := CompileWithIntent(c, nodes(), Binding{"Ethernet", "NL-VPN", "NL-TUN", 19091}, strings.Repeat("s", 32), intent)
		if e != nil {
			t.Fatal(e)
		}
		dns := out["dns"].(map[string]any)["nameserver-policy"].(map[string]any)
		servers := dns[domain].([]string)
		if env == "office" && !strings.HasSuffix(servers[0], "#PHYSICAL") {
			t.Fatal("suffix override DNS mismatch", servers)
		}
		if env == "home" && !strings.HasSuffix(servers[0], "#PERSONAL") {
			t.Fatal(servers)
		}
		if !strings.HasSuffix(dns[c.Company.Domains[0]].([]string)[0], "#CORP") {
			t.Fatal("company DNS was changed")
		}
	}
	legacy, e := RulePlan(c)
	if e != nil {
		t.Fatal(e)
	}
	ex, _ := Explain(legacy, domain)
	if ex.Winner.Target != "personal" {
		t.Fatal("legacy wrapper applied environment")
	}
	if c.ValidateForIntent(ChannelIntent{Environment: "unknown"}) == nil {
		t.Fatal("unknown environment accepted")
	}
}
func TestManualPersonalDirectKeepsCompanyResolverIsolated(t *testing.T) {
	c := fixture(t)
	out, e := CompileWithIntent(c, nil, Binding{"Ethernet", "NL-VPN", "NL-TUN", 19091}, strings.Repeat("s", 32), ChannelIntent{Company: true})
	if e != nil {
		t.Fatal(e)
	}
	dns := out["dns"].(map[string]any)["nameserver-policy"].(map[string]any)
	if !strings.HasSuffix(dns[c.Personal.Domains[0]].([]string)[0], "#PHYSICAL") {
		t.Fatal("personal resolver did not follow direct intent")
	}
	if !strings.HasSuffix(dns[c.Company.Domains[0]].([]string)[0], "#CORP") {
		t.Fatal("company DNS fell back")
	}
	for _, raw := range out["proxy-groups"].([]any) {
		g := raw.(map[string]any)
		if g["name"] == "PERSONAL" {
			p := g["proxies"].([]string)
			if len(p) != 2 || p[0] != "REJECT" || p[1] != "PHYSICAL" {
				t.Fatal(g)
			}
		}
	}
}
