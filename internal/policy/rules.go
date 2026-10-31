package policy

import (
	"fmt"
	"net/netip"
)

// Subscriptions can describe personal/direct/reject rules, never company access.
func ValidateRules(rules []Rule) error {
	if len(rules) > 20000 {
		return fieldError("personal_rules", "personal rule limit exceeded")
	}
	for index, r := range rules {
		field := fmt.Sprintf("personal_rules[%d]", index)
		if r.Target != "personal" && r.Target != "direct" && r.Target != "reject" {
			return fieldError(field+".target", "invalid personal rule target")
		}
		switch r.Type {
		case "DOMAIN", "DOMAIN-SUFFIX":
			if !ValidDomain(r.Value) {
				return fieldError(field+".value", "invalid personal rule domain")
			}
		case "IP-CIDR":
			p, e := netip.ParsePrefix(r.Value)
			if e != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() < 24 {
				return fieldError(field+".value", "personal CIDR rules require canonical IPv4 /24 through /32")
			}
			if _, e = IPv4(p.Addr().String()); e != nil {
				return fieldError(field+".value", "expected a usable IPv4 address")
			}
		default:
			return fieldError(field+".type", "unsupported personal rule type")
		}
	}
	return nil
}
