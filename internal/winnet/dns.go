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
	NameServers        string `json:"name_servers"`
	ProfileNameServers string `json:"profile_name_servers"`
}

func normalizeServers(s string) (string, error) {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	if len(parts) > 16 {
		return "", errors.New("too many configured DNS servers")
	}
	for i, p := range parts {
		a, e := netip.ParseAddr(p)
		if e != nil || !a.Is4() || a.IsUnspecified() || a.IsMulticast() {
			return "", errors.New("unsupported configured DNS server")
		}
		parts[i] = a.String()
	}
	return strings.Join(parts, ","), nil
}
func (d DNSSettings) Validate() error {
	for _, s := range []string{d.NameServers, d.ProfileNameServers} {
		if _, e := normalizeServers(s); e != nil {
			return e
		}
	}
	return nil
}
func SameDNS(a, b DNSSettings) bool {
	ax, e := normalizeServers(a.NameServers)
	if e != nil {
		return false
	}
	ay, e := normalizeServers(a.ProfileNameServers)
	if e != nil {
		return false
	}
	bx, e := normalizeServers(b.NameServers)
	if e != nil {
		return false
	}
	by, e := normalizeServers(b.ProfileNameServers)
	if e != nil {
		return false
	}
	return ax == bx && ay == by
}
