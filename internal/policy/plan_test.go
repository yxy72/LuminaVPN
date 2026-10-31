package policy

import (
	"reflect"
	"strings"
	"testing"
)

func TestSharedPlanPreservesCoreRulesAndExplainsPrecedence(t *testing.T) {
	c := fixture(t)
	c.PersonalRules = []Rule{{Type: "DOMAIN-SUFFIX", Value: "example.org", Target: "personal"}, {Type: "DOMAIN", Value: "sub.example.org", Target: "direct"}, {Type: "IP-CIDR", Value: "203.0.112.0/24", Target: "reject"}}
	plan, err := RulePlan(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ input, target, source string }{
		{c.Company.Domains[0], "company", "company.domains"},
		{c.Personal.Domains[0], "personal", "personal.domains"},
		{"www.baidu.com", "direct", "probes"},
		{"SUB.EXAMPLE.ORG.", "personal", "personal_rules"},
		{"example.org", "personal", "personal_rules"},
		{"notexample.org", "direct", "default"},
		{"203.0.112.99", "reject", "personal_rules"},
		{"198.19.1.2", "reject", "fake_ip_guard"},
		{"203.0.113.200", "direct", "default"},
	} {
		got, err := Explain(plan, tc.input)
		if err != nil || got.Winner.Target != tc.target || got.Winner.Source != tc.source || !got.StaticOnly || got.DNSResolved {
			t.Fatal(tc.input, got, err)
		}
		if tc.input == "SUB.EXAMPLE.ORG." && (len(got.Shadowed) != 2 || got.Shadowed[0].Index != 2) {
			t.Fatal("missing overridden rule", got)
		}
	}
	for _, input := range []string{"https://example.org/", "example.org:443", "*.example.org", "::1", "example.org/path"} {
		if _, err := Explain(plan, input); err == nil {
			t.Fatal("invalid query accepted", input)
		}
	}
	compiled, err := Compile(c, nodes(), Binding{"en5", "utun32", "utun33", 19091}, strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"DOMAIN,gateway.corp.example.com,CORP", "DOMAIN,gateway.corp.example.com,REJECT",
		"DOMAIN,git.corp.example.com,CORP", "DOMAIN,git.corp.example.com,REJECT",
		"DOMAIN,www.gstatic.com,PERSONAL", "DOMAIN,www.gstatic.com,REJECT",
		"DOMAIN,www.baidu.com,PHYSICAL", "DOMAIN-SUFFIX,example.org,PERSONAL", "DOMAIN,sub.example.org,PHYSICAL",
		"IP-CIDR,203.0.112.0/24,REJECT,no-resolve", "IP-CIDR,198.18.0.0/15,REJECT,no-resolve", "MATCH,PHYSICAL",
	}
	if !reflect.DeepEqual(compiled["rules"], want) {
		t.Fatalf("compiled rule ordering changed: %#v", compiled["rules"])
	}
}
