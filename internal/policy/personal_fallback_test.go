package policy

import (
	"reflect"
	"strings"
	"testing"
)

func TestAutomaticPersonalFallbackRoutesOnlyPersonalDNSThroughLease(t *testing.T) {
	c := fixture(t)
	c.DirectDNS = []string{"192.0.2.54", "192.0.2.55"}
	c.Personal.DNS = []string{"https://198.51.100.1/dns-query", "https://198.51.100.2/dns-query"}
	c.HomeOverrides = []Override{
		{Type: "domain_suffix", Value: "gstatic.com", Target: "personal"},
		{Type: "domain", Value: "office.example.com", Target: "direct"},
	}
	c.OfficeOverrides = []Override{
		{Type: "domain_suffix", Value: "gstatic.com", Target: "direct"},
		{Type: "domain", Value: c.Company.Domains[0], Target: "direct"},
	}
	c.PersonalRules = []Rule{
		{Type: "DOMAIN-SUFFIX", Value: "leased.example.org", Target: "personal"},
		{Type: "DOMAIN", Value: "exact.leased.example.org", Target: "direct"},
		{Type: "DOMAIN-SUFFIX", Value: "nested.leased.example.org", Target: "direct"},
		{Type: "DOMAIN-SUFFIX", Value: "direct.example.net", Target: "direct"},
		{Type: "DOMAIN", Value: "match.direct.example.net", Target: "personal"},
		{Type: "DOMAIN", Value: "blocked.example.org", Target: "reject"},
		{Type: "DOMAIN-SUFFIX", Value: "baidu.com", Target: "personal"},
		{Type: "IP-CIDR", Value: "203.0.112.0/24", Target: "personal"},
	}
	binding := Binding{"en5", "utun32", "utun33", 19091}
	secret := strings.Repeat("s", 32)
	direct := []string{"udp://192.0.2.54#PHYSICAL", "udp://192.0.2.55#PHYSICAL"}
	for _, tc := range []struct {
		name       string
		personal   bool
		lease      bool
		candidates []string
		resolver   []string
	}{
		{"proxy", true, false, []string{"REJECT", "P001"}, []string{"https://198.51.100.1/dns-query#PERSONAL", "https://198.51.100.2/dns-query#PERSONAL"}},
		{"manual off", false, false, []string{"REJECT", "PHYSICAL"}, direct},
		{"automatic", true, true, []string{"REJECT", "PHYSICAL"}, []string{"udp://192.0.2.54#PERSONAL", "udp://192.0.2.55#PERSONAL"}},
	} {
		for _, env := range []string{"home", "office"} {
			t.Run(tc.name+"/"+env, func(t *testing.T) {
				intent := ChannelIntent{Company: true, Personal: tc.personal, Environment: env}
				compile := CompileWithIntent
				if tc.lease {
					compile = CompilePersonalFallback
				}
				out, err := compile(c, nodes(), binding, secret, intent)
				if err != nil {
					t.Fatal(err)
				}
				groups := out["proxy-groups"].([]any)
				company := groups[0].(map[string]any)
				personal := groups[1].(map[string]any)
				if !reflect.DeepEqual(personal["proxies"], tc.candidates) || (tc.lease && personal["lumina-fallback-lease"] != true) || (!tc.lease && personal["lumina-fallback-lease"] != nil) || company["lumina-fallback-lease"] != nil {
					t.Fatal("unexpected selector membership or lease opt-in", groups)
				}
				if out["proxies"].([]any)[2].(Node)["name"] != "P001" {
					t.Fatal("named adapter missing for independent health checks")
				}
				dns := out["dns"].(map[string]any)
				for _, key := range []string{"nameserver", "direct-nameserver", "proxy-server-nameserver"} {
					if !reflect.DeepEqual(dns[key], direct) {
						t.Errorf("%s = %v, want %v", key, dns[key], direct)
					}
				}
				want := map[string][]string{
					c.Company.Domains[0]:          {"tcp://192.0.2.53:53#CORP"},
					c.Personal.Domains[0]:         tc.resolver,
					"+.gstatic.com":               tc.resolver,
					"+.leased.example.org":        tc.resolver,
					"exact.leased.example.org":    tc.resolver,
					"+.nested.leased.example.org": tc.resolver,
					"+.direct.example.net":        direct,
					"match.direct.example.net":    direct,
					"www.baidu.com":               direct,
					"+.baidu.com":                 tc.resolver,
					"blocked.example.org":         {"https://198.51.100.1/dns-query#REJECT", "https://198.51.100.2/dns-query#REJECT"},
				}
				if env == "office" {
					want[c.Personal.Domains[0]], want["+.gstatic.com"] = direct, direct
				} else {
					want["office.example.com"] = direct
				}
				policy := dns["nameserver-policy"].(map[string]any)
				for key, servers := range want {
					if !reflect.DeepEqual(policy[key], servers) {
						t.Errorf("DNS route %s = %v, want %v", key, policy[key], servers)
					}
				}
				rules := strings.Join(out["rules"].([]string), "\n")
				if !strings.Contains(rules, "IP-CIDR,203.0.112.0/24,PERSONAL,no-resolve") || !strings.HasSuffix(rules, "MATCH,PHYSICAL") {
					t.Error("personal CIDR or default payload route changed")
				}
			})
		}
	}
}

func TestAutomaticPersonalFallbackRequiresPersonalIntentAndPool(t *testing.T) {
	c := fixture(t)
	binding := Binding{"en5", "utun32", "utun33", 19091}
	secret := strings.Repeat("s", 32)
	if _, err := CompilePersonalFallback(c, nodes(), binding, secret, ChannelIntent{}); err == nil {
		t.Fatal("automatic fallback accepted manual off")
	}
	if _, err := CompilePersonalFallback(c, nil, binding, secret, ChannelIntent{Personal: true}); err == nil {
		t.Fatal("automatic fallback accepted missing candidates")
	}
	out, err := CompilePersonalFallback(c, nodes(), binding, secret, ChannelIntent{Personal: true})
	if err != nil {
		t.Fatal(err)
	}
	dns := out["dns"].(map[string]any)["nameserver-policy"].(map[string]any)
	if !reflect.DeepEqual(dns[c.Company.Domains[0]], []string{"rcode://refused"}) {
		t.Fatal("disabled company resolver opened during automatic fallback", dns[c.Company.Domains[0]])
	}
}
