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
	URL            string `json:"url"`
	Channel        string `json:"channel"`
	Purpose        string `json:"purpose,omitempty"`
	ExpectedStatus []int  `json:"expected_status,omitempty"`
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
	Version         int        `json:"version"`
	PersonalRules   []Rule     `json:"personal_rules,omitempty"`
	OfficeOverrides []Override `json:"office_overrides,omitempty"`
	HomeOverrides   []Override `json:"home_overrides,omitempty"`
	Company         Channel    `json:"company"`
	Personal        Channel    `json:"personal"`
	DirectDNS       []string   `json:"direct_dns"`
	VPN             VPN        `json:"vpn"`
	Ports           Ports      `json:"ports"`
	Probes          []Probe    `json:"probes"`
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
	return DecodeForIntent(data, DefaultIntent())
}
func DecodeForIntent(data []byte, intent ChannelIntent) (Config, error) {
	return decode(data, intent, true)
}

// DecodeForStorage accepts an incomplete first-use profile. It does not
// authorize a running takeover; every supplied value is still validated.
func DecodeForStorage(data []byte) (Config, error) {
	return decode(data, ChannelIntent{}, false)
}

func decode(data []byte, intent ChannelIntent, requireBase bool) (Config, error) {
	var c Config
	if len(data) > 1<<20 {
		return c, errors.New("policy exceeds 1 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, decodeError(data, err)
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("multiple policy values")
	}
	return c, c.validate(intent, requireBase)
}

func (c Config) Validate() error {
	return c.ValidateForIntent(DefaultIntent())
}

// ValidateForIntent validates every supplied field, while disabled channels do
// not require credentials, resolvers or health probes that will never be used.
func (c Config) ValidateForIntent(intent ChannelIntent) error {
	return c.validate(intent, true)
}

// ValidateForStorage validates an editable profile without requiring settings
// for inactive channels or the base runtime. Starting a takeover must separately
// use ValidateForIntent with its actual channel intent.
func (c Config) ValidateForStorage() error {
	return c.validate(ChannelIntent{}, false)
}

func (c Config) validate(intent ChannelIntent, requireBase bool) error {
	if _, err := c.environmentRules(intent); err != nil {
		return err
	}
	if _, err := overrideRules(c.OfficeOverrides); err != nil {
		return err
	}
	if _, err := overrideRules(c.HomeOverrides); err != nil {
		return err
	}
	if err := ValidateRules(c.PersonalRules); err != nil {
		return err
	}
	if c.Version != 1 {
		return fieldError("version", "unsupported policy version")
	}
	if c.Ports.Proxy < 1024 || c.Ports.Proxy > 65535 {
		return fieldError("ports.proxy", "expected a port from 1024 through 65535")
	}
	if c.Ports.DNS < 1 || c.Ports.DNS > 65535 || c.Ports.Proxy == c.Ports.DNS {
		return fieldError("ports.dns", "expected a port from 1 through 65535, different from ports.proxy")
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
		enabled := intent.Company
		if i == 1 {
			enabled = intent.Personal
		}
		if (enabled && len(ch.Domains)+len(ch.CIDRs) == 0) || len(ch.Domains)+len(ch.CIDRs) > 128 {
			return fieldError(owner, "needs 1–128 explicit targets")
		}
		for index, domain := range ch.Domains {
			field := fmt.Sprintf("%s.domains[%d]", owner, index)
			if !ValidDomain(domain) {
				return fieldError(field, "invalid exact domain")
			}
			if _, ok := owners[domain]; ok {
				return fieldError(field, "duplicate or overlapping domain authorization")
			}
			owners[domain] = owner
		}
		for index, raw := range ch.CIDRs {
			field := fmt.Sprintf("%s.cidrs[%d]", owner, index)
			p, err := netip.ParsePrefix(raw)
			if err != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() < 24 {
				return fieldError(field, "v1 CIDR grants must be canonical IPv4 /24 through /32")
			}
			if _, err = IPv4(p.Addr().String()); err != nil {
				return fieldError(field, "expected a usable IPv4 address")
			}
			for _, old := range prefixes {
				if old.p.Overlaps(p) {
					return fieldError(field, "overlapping CIDR authorization")
				}
			}
			prefixes = append(prefixes, struct {
				p     netip.Prefix
				owner string
			}{p, owner})
		}
		if (enabled && len(ch.DNS) == 0) || len(ch.DNS) > 4 {
			return fieldError(owner+".dns", "needs 1–4 explicit DNS servers")
		}
	}
	for _, group := range []struct {
		field   string
		servers []string
	}{{"company.dns", c.Company.DNS}, {"direct_dns", c.DirectDNS}} {
		for index, s := range group.servers {
			if _, err := IPv4(s); err != nil {
				return fieldError(fmt.Sprintf("%s[%d]", group.field, index), "DNS must use explicit IPv4 addresses")
			}
		}
	}
	if (requireBase && len(c.DirectDNS) == 0) || len(c.DirectDNS) > 4 {
		return fieldError("direct_dns", "needs 1–4 explicit DNS servers")
	}
	for index, s := range c.Personal.DNS {
		field := fmt.Sprintf("personal.dns[%d]", index)
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Path != "/dns-query" {
			return fieldError(field, "personal DNS must be explicit HTTPS /dns-query endpoints")
		}
		if _, err := IPv4(u.Hostname()); err != nil {
			return fieldError(field, "personal DNS bootstrap must use a literal IPv4 address")
		}
		if u.Port() != "" && u.Port() != "443" {
			return fieldError(field, "personal DNS uses HTTPS port 443")
		}
	}
	u, err := url.Parse(c.VPN.Server)
	if (intent.Company || c.VPN.Server != "") && (err != nil || u.Scheme != "https" || !validPort(u) || !ValidDomain(u.Hostname()) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/")) {
		return fieldError("vpn.server", "VPN server must be a credential-free HTTPS hostname")
	}
	if _, err := IPv4(c.VPN.EndpointIPv4); (intent.Company || c.VPN.EndpointIPv4 != "") && err != nil {
		return fieldError("vpn.endpoint_ipv4", "VPN needs an explicit IPv4 bootstrap endpoint")
	}
	seen := map[string]bool{}
	for index, p := range c.Probes {
		field := fmt.Sprintf("probes[%d]", index)
		if err := p.validatePurpose(field); err != nil {
			return err
		}
		u, err := url.Parse(p.URL)
		if err != nil || u.Scheme != "https" || !validPort(u) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(p.URL) > 1024 {
			return fieldError(field+".url", "health probes must be credential-free HTTPS URLs")
		}
		if p.Channel != "company" && p.Channel != "personal" && p.Channel != "direct" {
			return fieldError(field+".channel", "invalid probe channel")
		}
		if p.Channel == "direct" {
			if !ValidDomain(u.Hostname()) || owners[u.Hostname()] != "" {
				return fieldError(field+".url", "direct probe conflicts with an authorized channel")
			}
		} else if owners[u.Hostname()] != p.Channel {
			return fieldError(field+".url", "probe domain is not in its channel's exact whitelist")
		}
		seen[p.Channel] = true
	}
	if (intent.Company && !seen["company"]) || (intent.Personal && !seen["personal"]) || (requireBase && !seen["direct"]) {
		return fieldError("probes", "company, personal and direct HTTPS probes are required")
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
