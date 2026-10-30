package policy

import (
	"strings"
	"testing"
)

func TestRulePrecedenceMatchesDNS(t *testing.T) {
	c := fixture(t)
	c.PersonalRules = []Rule{
		{"DOMAIN-SUFFIX", "example.com", "direct"},
		{"DOMAIN", c.Company.Domains[0], "reject"},
		{"DOMAIN", "child.example.com", "personal"},
		{"DOMAIN-SUFFIX", "nested.example.com", "personal"},
		{"DOMAIN", "first.other.org", "reject"},
		{"DOMAIN-SUFFIX", "other.org", "personal"},
		{"DOMAIN-SUFFIX", "baidu.com", "reject"},
		{"IP-CIDR", "203.0.112.0/24", "personal"},
	}
	out, e := Compile(c, nodes(), Binding{"en5", "utun32", "utun33", 19091}, strings.Repeat("x", 32))
	if e != nil {
		t.Fatal(e)
	}
	d := out["dns"].(map[string]any)["nameserver-policy"].(map[string]any)
	for name, group := range map[string]string{c.Company.Domains[0]: "CORP", "child.example.com": "PHYSICAL", "+.nested.example.com": "PHYSICAL", "first.other.org": "REJECT", "+.other.org": "PERSONAL", "www.baidu.com": "PHYSICAL"} {
		if !strings.HasSuffix(d[name].([]string)[0], "#"+group) {
			t.Fatal("DNS differs from first routing match", name, d[name])
		}
	}
	rules := strings.Join(out["rules"].([]string), "\n")
	if strings.Index(rules, "DOMAIN,"+c.Company.Domains[0]+",CORP") > strings.Index(rules, "DOMAIN-SUFFIX,example.com,PHYSICAL") || strings.Index(rules, "DOMAIN,www.baidu.com,PHYSICAL") > strings.Index(rules, "DOMAIN-SUFFIX,baidu.com,REJECT") {
		t.Fatal("local rules lost precedence")
	}
	if !strings.Contains(rules, "IP-CIDR,203.0.112.0/24,PERSONAL,no-resolve") {
		t.Fatal("CIDR not compiled")
	}
}
func TestPersonalRulesRejectCompanyGrantsAndBroadCIDRs(t *testing.T) {
	for _, r := range []Rule{{"DOMAIN", "example.org", "company"}, {"MATCH", "", "personal"}, {"IP-CIDR", "0.0.0.0/0", "direct"}, {"IP-CIDR", "198.19.0.0/24", "direct"}, {"DOMAIN-SUFFIX", "*.example.org", "personal"}} {
		if ValidateRules([]Rule{r}) == nil {
			t.Fatal("unsafe rule accepted", r)
		}
	}
}
