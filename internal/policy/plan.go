package policy

import (
	"errors"
	"net/netip"
	"net/url"
	"strings"
)

// PlannedRule is the ordered input shared by the core compiler and explanation
// tools. Index is one-based within Source; zero denotes a built-in rule.
type PlannedRule struct {
	Rule
	Source string `json:"source"`
	Index  int    `json:"index"`
	Guard  bool   `json:"guard,omitempty"`
}

func RulePlan(c Config) ([]PlannedRule, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	var plan []PlannedRule
	for channelIndex, ch := range []Channel{c.Company, c.Personal} {
		target := []string{"company", "personal"}[channelIndex]
		for i, domain := range ch.Domains {
			r := PlannedRule{Rule: Rule{Type: "DOMAIN", Value: domain, Target: target}, Source: target + ".domains", Index: i + 1}
			plan = append(plan, r)
			r.Target, r.Guard = "reject", true
			plan = append(plan, r)
		}
		for i, prefix := range ch.CIDRs {
			r := PlannedRule{Rule: Rule{Type: "IP-CIDR", Value: prefix, Target: target}, Source: target + ".cidrs", Index: i + 1}
			plan = append(plan, r)
			r.Target, r.Guard = "reject", true
			plan = append(plan, r)
		}
	}
	for i, p := range c.Probes {
		if p.Channel == "direct" {
			u, _ := url.Parse(p.URL)
			plan = append(plan, PlannedRule{Rule: Rule{Type: "DOMAIN", Value: u.Hostname(), Target: "direct"}, Source: "probes", Index: i + 1})
		}
	}
	for i, r := range c.PersonalRules {
		plan = append(plan, PlannedRule{Rule: r, Source: "personal_rules", Index: i + 1})
	}
	plan = append(plan, PlannedRule{Rule: Rule{Type: "IP-CIDR", Value: "198.18.0.0/15", Target: "reject"}, Source: "fake_ip_guard", Guard: true}, PlannedRule{Rule: Rule{Type: "MATCH", Target: "direct"}, Source: "default"})
	return plan, nil
}

func (r PlannedRule) CoreRule() string {
	group := map[string]string{"company": "CORP", "personal": "PERSONAL", "direct": "PHYSICAL", "reject": "REJECT"}[r.Target]
	if r.Type == "MATCH" {
		return "MATCH," + group
	}
	line := r.Type + "," + r.Value + "," + group
	if r.Type == "IP-CIDR" {
		line += ",no-resolve"
	}
	return line
}

type Explanation struct {
	Target      string        `json:"target"`
	Winner      PlannedRule   `json:"winner"`
	Shadowed    []PlannedRule `json:"shadowed"`
	StaticOnly  bool          `json:"static_only"`
	DNSResolved bool          `json:"dns_resolved"`
}

// Explain never resolves a hostname. Literal IPs match address rules; names
// match domain rules. Live authorization, leases and path health are separate.
func Explain(plan []PlannedRule, target string) (Explanation, error) {
	target = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	out := Explanation{Target: target, StaticOnly: true, Shadowed: []PlannedRule{}}
	addr, addrErr := netip.ParseAddr(target)
	if addrErr == nil && !addr.Is4() {
		return out, errors.New("rule explanation supports IPv4 or an exact hostname")
	}
	if addrErr != nil && !ValidDomain(target) {
		return out, errors.New("expected an exact hostname or IPv4 address, without URL or port")
	}
	found := false
	for _, r := range plan {
		match := false
		switch r.Type {
		case "MATCH":
			match = true
		case "DOMAIN":
			match = addrErr != nil && target == r.Value
		case "DOMAIN-SUFFIX":
			match = addrErr != nil && (target == r.Value || strings.HasSuffix(target, "."+r.Value))
		case "IP-CIDR":
			prefix, err := netip.ParsePrefix(r.Value)
			match = addrErr == nil && err == nil && prefix.Contains(addr)
		}
		if !match {
			continue
		}
		if !found {
			out.Winner, found = r, true
		} else {
			out.Shadowed = append(out.Shadowed, r)
		}
	}
	if !found {
		return out, errors.New("rule plan has no default decision")
	}
	return out, nil
}
