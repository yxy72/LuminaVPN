package policy

import (
	"errors"
	"net/netip"
)

// Subscriptions can describe personal/direct/reject rules, never company access.
func ValidateRules(rules []Rule) error {
	if len(rules) > 20000 {
		return errors.New("personal rule limit exceeded")
	}
	for _, r := range rules {
		if r.Target != "personal" && r.Target != "direct" && r.Target != "reject" {
			return errors.New("invalid personal rule target")
		}
		switch r.Type {
		case "DOMAIN", "DOMAIN-SUFFIX":
			if !ValidDomain(r.Value) {
				return errors.New("invalid personal rule domain")
			}
		case "IP-CIDR":
			p, e := netip.ParsePrefix(r.Value)
			if e != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() < 24 {
				return errors.New("personal CIDR rules require canonical IPv4 /24 through /32")
			}
			if _, e = IPv4(p.Addr().String()); e != nil {
				return e
			}
		default:
			return errors.New("unsupported personal rule type")
		}
	}
	return nil
}
