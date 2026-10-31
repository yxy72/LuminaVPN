package policy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPolicyDiagnosticsIdentifyFieldsWithoutValues(t *testing.T) {
	for _, tc := range []struct {
		field string
		edit  func(*Config)
	}{
		{"company.domains[1]", func(c *Config) { c.Company.Domains = append(c.Company.Domains[:1], "PRIVATE.invalid") }},
		{"personal.domains[1]", func(c *Config) { c.Personal.Domains = append(c.Personal.Domains[:1], c.Company.Domains[0]) }},
		{"company.cidrs[0]", func(c *Config) { c.Company.CIDRs = []string{"10.0.0.0/8"} }},
		{"company.dns[0]", func(c *Config) { c.Company.DNS = []string{"PRIVATE.invalid"} }},
		{"personal.dns[0]", func(c *Config) { c.Personal.DNS = []string{"https://PRIVATE.invalid/dns-query"} }},
		{"direct_dns[0]", func(c *Config) { c.DirectDNS = []string{"PRIVATE.invalid"} }},
		{"vpn.server", func(c *Config) { c.VPN.Server = "https://SECRET@vpn.example.com/" }},
		{"vpn.endpoint_ipv4", func(c *Config) { c.VPN.EndpointIPv4 = "PRIVATE.invalid" }},
		{"ports.dns", func(c *Config) { c.Ports.DNS = c.Ports.Proxy }},
		{"personal_rules[0].value", func(c *Config) {
			c.PersonalRules = []Rule{{Type: "DOMAIN", Target: "personal", Value: "PRIVATE.invalid"}}
		}},
		{"probes[0].url", func(c *Config) { c.Probes[0].URL = "https://SECRET@PRIVATE.invalid/" }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			cfg := fixture(t)
			tc.edit(&cfg)
			raw, _ := json.Marshal(cfg)
			_, err := Decode(raw)
			var detail *ValidationError
			if !errors.As(err, &detail) || detail.Field != tc.field {
				t.Fatal(err)
			}
			if strings.Contains(err.Error(), "PRIVATE") || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), cfg.Company.Domains[0]) {
				t.Fatal("diagnostic exposed private data", err)
			}
		})
	}
}

func TestPolicyJSONDiagnosticsLocateSyntaxAndTypeErrors(t *testing.T) {
	for _, tc := range []struct {
		raw          string
		line, column int
	}{
		{"{\n\"version\":@}", 2, 11},
		{"{\n\"version\":\"SECRET\"}", 2, 18},
		{"{\n\"version\":", 2, 11},
	} {
		_, err := Decode([]byte(tc.raw))
		var detail *ValidationError
		if !errors.As(err, &detail) || detail.Line != tc.line || detail.Column != tc.column || strings.Contains(err.Error(), "SECRET") {
			t.Fatal(tc, err)
		}
	}
	_, err := Decode([]byte(`{"PRIVATE.invalid":"SECRET"}`))
	if err == nil || strings.Contains(err.Error(), "PRIVATE") || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("unknown field name/value escaped", err)
	}
}
