package mobile_test

import (
	"encoding/json"
	"strings"
	"testing"

	"netlaunch/sdk/mobile"
)

const fullPolicy = `{
  "version": 1,
  "company": {"domains":["intranet.example.com"], "dns":["192.0.2.53"]},
  "personal": {"domains":["overseas.example.com"], "dns":["https://192.0.2.54/dns-query"]},
  "office_overrides": [
    {"type":"domain","value":"intranet.example.com","target":"direct"},
    {"type":"domain","value":"overseas.example.com","target":"direct"}
  ],
  "direct_dns":["192.0.2.55"],
  "vpn":{"server":"https://vpn.example.com","endpoint_ipv4":"192.0.2.1"},
  "ports":{"proxy":17890,"dns":53},
  "probes":[
    {"url":"https://intranet.example.com/","channel":"company"},
    {"url":"https://overseas.example.com/","channel":"personal"},
    {"url":"https://direct.example.com/","channel":"direct"}
  ]
}`

func TestRulePlanUsesSharedPriorities(t *testing.T) {
	tests := []struct {
		name, environment, host, target string
		company                         bool
	}{
		{"company defeats office override", "office", "INTRANET.EXAMPLE.COM.", "company", true},
		{"disabled company cannot go direct", "office", "intranet.example.com", "reject", false},
		{"office override applies to personal", "office", "overseas.example.com", "direct", true},
		{"shared rules apply at home", "home", "overseas.example.com", "personal", true},
		{"unknown destination uses direct", "", "other.example.com", "direct", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := mobile.BuildRulePlan([]byte(fullPolicy), tc.company, true, tc.environment)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := plan.ExplainJSON(tc.host)
			if err != nil {
				t.Fatal(err)
			}
			var explanation struct {
				Winner struct {
					Target string `json:"target"`
				} `json:"winner"`
				StaticOnly  bool `json:"static_only"`
				DNSResolved bool `json:"dns_resolved"`
			}
			if err := json.Unmarshal(raw, &explanation); err != nil {
				t.Fatal(err)
			}
			if explanation.Winner.Target != tc.target || !explanation.StaticOnly || explanation.DNSResolved {
				t.Fatalf("unexpected explanation: %s", raw)
			}
		})
	}

	plan, err := mobile.BuildRulePlan([]byte(fullPolicy), true, true, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := plan.RulesJSON()
	if err != nil {
		t.Fatal(err)
	}
	var rules []struct {
		Kind   string `json:"type"`
		Target string `json:"target"`
	}
	if err := json.Unmarshal(raw, &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 || rules[len(rules)-1].Kind != "MATCH" || rules[len(rules)-1].Target != "direct" {
		t.Fatalf("missing default rule: %s", raw)
	}
}

func TestStoredPolicyValidationDiffersFromConnectionIntent(t *testing.T) {
	const incomplete = `{"version":1,"ports":{"proxy":17890,"dns":53}}`
	if err := mobile.ValidateStoredPolicyJSON([]byte(incomplete)); err != nil {
		t.Fatal(err)
	}
	if _, err := mobile.BuildRulePlan([]byte(incomplete), false, false, ""); err == nil {
		t.Fatal("incomplete stored policy passed connection validation")
	}
	const privateMarker = "private-example-token"
	bad := strings.Replace(incomplete, `"version":1`, `"version":"`+privateMarker+`"`, 1)
	if err := mobile.ValidateStoredPolicyJSON([]byte(bad)); err == nil || strings.Contains(err.Error(), privateMarker) {
		t.Fatalf("expected a redacted validation error, got %v", err)
	}
	if err := mobile.ValidateStoredPolicyJSON([]byte(strings.Replace(incomplete, "1,", "2,", 1))); err == nil {
		t.Fatal("unsupported policy version passed validation")
	}
}

func TestRuleSubscriptionCannotGrantCompanyAccess(t *testing.T) {
	data := []byte("rules:\n  - DOMAIN,proxy.example.com,PROXY\n  - DOMAIN,private-example.com,COMPANY\n  - IP-CIDR,192.0.2.0/24,DIRECT,no-resolve\n")
	raw, err := mobile.ParseRuleSubscriptionJSON(data, "classical", "", false)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Rules []struct {
			Target string `json:"target"`
		} `json:"rules"`
		SourceIndexes []int `json:"source_indexes"`
		Issues        []struct {
			Index  int    `json:"index"`
			Reason string `json:"reason"`
		} `json:"issues"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Rules) != 2 || report.Rules[0].Target != "personal" || report.Rules[1].Target != "direct" {
		t.Fatalf("unexpected parsed rules: %s", raw)
	}
	if len(report.SourceIndexes) != 2 || report.SourceIndexes[0] != 1 || report.SourceIndexes[1] != 3 ||
		len(report.Issues) != 1 || report.Issues[0].Index != 2 || report.Issues[0].Reason != "unmapped_group" ||
		strings.Contains(string(raw), "private-example.com") {
		t.Fatalf("unexpected source indexes or issues: %s", raw)
	}
	if _, err := mobile.ParseRuleSubscriptionJSON(data, "classical", "", true); err == nil {
		t.Fatal("strict parsing accepted a skipped rule")
	}
	if _, err := mobile.ParseRuleSubscriptionJSON(data, "classical", "company", false); err == nil {
		t.Fatal("company fallback target was accepted")
	}
}
