package policy

import (
	"errors"
	"net/netip"
	"net/url"
)

// Control endpoints are physical bootstrap paths, not business authorizations.
func ValidateEndpoints(c Config, nodes []Node) error {
	control := []string{c.VPN.EndpointIPv4}
	for _, n := range nodes {
		if ip, ok := n["server"].(string); ok {
			control = append(control, ip)
		}
	}
	for _, raw := range control {
		if ValidDomain(raw) {
			u, e := url.Parse(c.VPN.Server)
			if e != nil {
				return e
			}
			if raw == u.Hostname() {
				return errors.New("personal node overlaps the VPN control hostname")
			}
			for _, ch := range []Channel{c.Company, c.Personal} {
				for _, domain := range ch.Domains {
					if raw == domain {
						return errors.New("physical node hostname overlaps a business domain")
					}
				}
			}
			continue
		}
		ip, e := IPv4(raw)
		if e != nil {
			return e
		}
		for _, dns := range c.Company.DNS {
			if raw == dns {
				return errors.New("physical bootstrap endpoint overlaps company DNS")
			}
		}
		for _, ch := range []Channel{c.Company, c.Personal} {
			for _, r := range ch.CIDRs {
				p, e := netip.ParsePrefix(r)
				if e != nil {
					return e
				}
				if p.Contains(ip) {
					return errors.New("physical bootstrap endpoint overlaps a business CIDR")
				}
			}
		}
	}
	return nil
}
