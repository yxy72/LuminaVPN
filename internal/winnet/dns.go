package winnet

import (
	"errors"
	"net/netip"
	"strings"
)

// DNSSettings records configured static servers, not DHCP's current response.
// An empty NameServers restores automatic DNS selection. ProfileNameServers
// is an external setting that NetLaunch observes but never changes.
type DNSSettings struct {
	IPv6               bool   `json:"ipv6,omitempty"`
	NameServers        string `json:"name_servers"`
	ProfileNameServers string `json:"profile_name_servers"`
}

func normalizeServers(s string, ipv6 bool) (string, error) {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	if len(parts) > 16 {
		return "", errors.New("too many configured DNS servers")
	}
	for i, p := range parts {
		a, e := netip.ParseAddr(p)
		if e != nil || a.Is4() == ipv6 || a.Is4In6() || a.IsUnspecified() || a.IsMulticast() {
			return "", errors.New("unsupported configured DNS server")
		}
		parts[i] = a.String()
	}
	return strings.Join(parts, ","), nil
}
func (d DNSSettings) Validate() error {
	for _, s := range []string{d.NameServers, d.ProfileNameServers} {
		if _, e := normalizeServers(s, d.IPv6); e != nil {
			return e
		}
	}
	return nil
}
func SameDNS(a, b DNSSettings) bool {
	if a.IPv6 != b.IPv6 {
		return false
	}
	ax, e := normalizeServers(a.NameServers, a.IPv6)
	if e != nil {
		return false
	}
	ay, e := normalizeServers(a.ProfileNameServers, a.IPv6)
	if e != nil {
		return false
	}
	bx, e := normalizeServers(b.NameServers, b.IPv6)
	if e != nil {
		return false
	}
	by, e := normalizeServers(b.ProfileNameServers, b.IPv6)
	if e != nil {
		return false
	}
	return ax == bx && ay == by
}
