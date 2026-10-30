// Package policy owns the authorization policy shared by every platform.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type Channel struct {
	Domains []string `json:"domains"`
	CIDRs   []string `json:"cidrs"`
	DNS     []string `json:"dns"`
}
type VPN struct {
	Server       string `json:"server"`
	EndpointIPv4 string `json:"endpoint_ipv4"`
}
type Probe struct {
	URL     string `json:"url"`
	Channel string `json:"channel"`
}
type Ports struct {
	Proxy int `json:"proxy"`
	DNS   int `json:"dns"`
}
type Rule struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Target string `json:"target"`
}

type Config struct {
	Version       int      `json:"version"`
	PersonalRules []Rule   `json:"personal_rules,omitempty"`
	Company       Channel  `json:"company"`
	Personal      Channel  `json:"personal"`
	DirectDNS     []string `json:"direct_dns"`
	VPN           VPN      `json:"vpn"`
	Ports         Ports    `json:"ports"`
	Probes        []Probe  `json:"probes"`
}

var domainRE = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var interfaceRE = regexp.MustCompile(`^[\pL\pN][\pL\pN _.-]{0,127}$`)

func ValidDomain(s string) bool {
	if _, e := netip.ParseAddr(s); e == nil {
		return false
	}
	return len(s) <= 253 && domainRE.MatchString(s)
}

// Aliases are passed as structured JSON/native arguments. Accept ordinary
// Windows aliases (including localized names), while excluding shell syntax,
// control characters and leading/trailing whitespace.
func ValidInterface(s string) bool { return strings.TrimSpace(s) == s && interfaceRE.MatchString(s) }
func IPv4(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || s == "255.255.255.255" || netip.MustParsePrefix("198.18.0.0/15").Contains(a) {
		return netip.Addr{}, errors.New("expected a usable IPv4 address")
	}
	return a, nil
}
func Decode(data []byte) (Config, error) {
	var c Config
	if len(data) > 1<<20 {
		return c, errors.New("policy exceeds 1 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, errors.New("invalid policy JSON or unknown field")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("multiple policy values")
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if err := ValidateRules(c.PersonalRules); err != nil {
		return err
	}
	if c.Version != 1 {
		return errors.New("unsupported policy version")
	}
	if c.Ports.Proxy < 1024 || c.Ports.Proxy > 65535 || c.Ports.DNS < 1 || c.Ports.DNS > 65535 || c.Ports.Proxy == c.Ports.DNS {
		return errors.New("invalid or overlapping local ports")
	}
	// Version 1 intentionally supports exact names and narrow IPv4 grants.
	// DNS suffix grants require on-demand route leases and are not silently approximated.
	owners := map[string]string{}
	var prefixes []struct {
		p     netip.Prefix
		owner string
	}
	for i, ch := range []Channel{c.Company, c.Personal} {
		owner := []string{"company", "personal"}[i]
		if len(ch.Domains)+len(ch.CIDRs) == 0 || len(ch.Domains)+len(ch.CIDRs) > 128 {
			return fmt.Errorf("%s needs 1–128 explicit targets", owner)
		}
		for _, domain := range ch.Domains {
			if !ValidDomain(domain) {
				return fmt.Errorf("%s has an invalid exact domain", owner)
			}
			if _, ok := owners[domain]; ok {
				return errors.New("duplicate or overlapping domain authorization")
			}
			owners[domain] = owner
		}
		for _, raw := range ch.CIDRs {
			p, err := netip.ParsePrefix(raw)
			if err != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() < 24 {
				return errors.New("v1 CIDR grants must be canonical IPv4 /24 through /32")
			}
			if _, err = IPv4(p.Addr().String()); err != nil {
				return err
			}
			for _, old := range prefixes {
				if old.p.Overlaps(p) {
					return errors.New("overlapping CIDR authorization")
				}
			}
			prefixes = append(prefixes, struct {
				p     netip.Prefix
				owner string
			}{p, owner})
		}
		if len(ch.DNS) == 0 || len(ch.DNS) > 4 {
			return fmt.Errorf("%s needs explicit DNS servers", owner)
		}
	}
	for _, s := range append(append([]string{}, c.Company.DNS...), c.DirectDNS...) {
		if _, err := IPv4(s); err != nil {
			return errors.New("company/direct DNS must use explicit IPv4 addresses")
		}
	}
	if len(c.DirectDNS) == 0 || len(c.DirectDNS) > 4 {
		return errors.New("direct DNS is required")
	}
	for _, s := range c.Personal.DNS {
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Path != "/dns-query" {
			return errors.New("personal DNS must be explicit HTTPS /dns-query endpoints")
		}
		if _, err := IPv4(u.Hostname()); err != nil {
			return errors.New("personal DNS bootstrap must use a literal IPv4 address")
		}
		if u.Port() != "" && u.Port() != "443" {
			return errors.New("personal DNS uses HTTPS port 443")
		}
	}
	u, err := url.Parse(c.VPN.Server)
	if err != nil || u.Scheme != "https" || !validPort(u) || !ValidDomain(u.Hostname()) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("VPN server must be a credential-free HTTPS hostname")
	}
	if _, err := IPv4(c.VPN.EndpointIPv4); err != nil {
		return errors.New("VPN needs an explicit IPv4 bootstrap endpoint")
	}
	seen := map[string]bool{}
	for _, p := range c.Probes {
		u, err := url.Parse(p.URL)
		if err != nil || u.Scheme != "https" || !validPort(u) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(p.URL) > 1024 {
			return errors.New("health probes must be credential-free HTTPS URLs")
		}
		if p.Channel != "company" && p.Channel != "personal" && p.Channel != "direct" {
			return errors.New("invalid probe channel")
		}
		if p.Channel == "direct" {
			if !ValidDomain(u.Hostname()) || owners[u.Hostname()] != "" {
				return errors.New("direct probe conflicts with an authorized channel")
			}
		} else if owners[u.Hostname()] != p.Channel {
			return errors.New("probe domain is not in its channel's exact whitelist")
		}
		seen[p.Channel] = true
	}
	if !seen["company"] || !seen["personal"] || !seen["direct"] {
		return errors.New("company, personal and direct HTTPS probes are required")
	}
	return nil
}

func (c Config) IsCompany(domain string) bool {
	for _, v := range c.Company.Domains {
		if v == strings.ToLower(domain) {
			return true
		}
	}
	return false
}

func validPort(u *url.URL) bool {
	if u.Port() == "" {
		return !strings.HasSuffix(u.Host, ":")
	}
	p, e := strconv.Atoi(u.Port())
	return e == nil && p > 0 && p <= 65535
}
