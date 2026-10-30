//go:build darwin

package platform

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"netlaunch/internal/policy"
)

func Supported() bool { return true }
func Discover() (Network, error) {
	ctx := context.Background()
	order, e := Command(ctx, "/usr/sbin/networksetup", "-listnetworkserviceorder")
	if e != nil {
		return Network{}, e
	}
	services := map[string]string{}
	current := ""
	serviceRE := regexp.MustCompile(`^\([0-9]+\) (.+)$`)
	deviceRE := regexp.MustCompile(`Device: (en[0-9]+)\)`)
	for _, line := range strings.Split(order, "\n") {
		if m := serviceRE.FindStringSubmatch(line); m != nil {
			current = m[1]
		}
		if m := deviceRE.FindStringSubmatch(line); m != nil && current != "" {
			services[m[1]] = current
		}
	}
	names := []string{}
	for name := range services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		i, e := net.InterfaceByName(name)
		if e != nil || i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		address := ""
		for _, raw := range addrs {
			p, e := netip.ParsePrefix(raw.String())
			if e == nil && p.Addr().Is4() {
				if _, e = policy.IPv4(p.Addr().String()); e == nil {
					address = p.Addr().String()
					break
				}
			}
		}
		if address == "" {
			continue
		}
		r, e := Command(ctx, "/sbin/route", "-n", "get", "-ifscope", name, "default")
		if e != nil {
			continue
		}
		f := Fields(r)
		if f["interface"] != name {
			continue
		}
		if _, e = policy.IPv4(f["gateway"]); e != nil {
			continue
		}
		return Network{name, address, f["gateway"], services[name]}, nil
	}
	return Network{}, errors.New("no active physical IPv4 network with a managed service")
}
func Fields(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}
func Interfaces() (map[string]bool, error) {
	items, e := net.Interfaces()
	r := map[string]bool{}
	for _, i := range items {
		r[i.Name] = true
	}
	return r, e
}
func Candidates() (string, string, error) {
	items, e := Interfaces()
	if e != nil {
		return "", "", e
	}
	names := []string{}
	for i := 32; i < 240; i++ {
		n := "utun" + strconv.Itoa(i)
		if !items[n] {
			names = append(names, n)
		}
		if len(names) == 2 {
			return names[0], names[1], nil
		}
	}
	return "", "", errors.New("no free candidate interfaces")
}
func BoundDial(iface string) func(context.Context, string, string) (net.Conn, error) {
	return BoundDialIdentity(iface, 0)
}
func BoundDialIdentity(iface string, expectedIndex int) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if !policy.ValidInterface(iface) {
			return nil, errors.New("invalid bound interface")
		}
		i, e := net.InterfaceByName(iface)
		if e != nil || (expectedIndex != 0 && i.Index != expectedIndex) || i.Flags&net.FlagUp == 0 {
			return nil, errors.New("bound interface identity unavailable")
		}
		if network != "tcp4" {
			return nil, errors.New("bound dial requires tcp4")
		}
		if a, e := netip.ParseAddrPort(address); e != nil || !a.Addr().Is4() {
			return nil, errors.New("bound dial requires literal IPv4")
		}

		d := net.Dialer{Timeout: 3 * time.Second, Control: func(_, _ string, raw syscall.RawConn) error {
			var inner error
			e := raw.Control(func(fd uintptr) { inner = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 25, i.Index) })
			if e != nil {
				return e
			}
			return inner
		}}
		return d.DialContext(ctx, "tcp4", address)
	}
}
func DNS(service string) ([]string, error) {
	s, e := Command(context.Background(), "/usr/sbin/networksetup", "-getdnsservers", service)
	if e != nil {
		return nil, e
	}
	if strings.Contains(s, "There aren't any DNS Servers") {
		return []string{}, nil
	}
	out := strings.Fields(s)
	for _, s := range out {
		if _, e := netip.ParseAddr(s); e != nil {
			return nil, errors.New("unrecognized system DNS response")
		}
	}
	return out, nil
}
func SetDNS(service string, values []string) error {
	for _, s := range values {
		if _, e := netip.ParseAddr(s); e != nil {
			return errors.New("invalid DNS value")
		}
	}
	if len(values) == 0 {
		values = []string{"Empty"}
	}
	_, e := Command(context.Background(), "/usr/sbin/networksetup", append([]string{"-setdnsservers", service}, values...)...)
	return e
}
func FlushDNS() {
	_, _ = Command(context.Background(), "/usr/bin/dscacheutil", "-flushcache")
	_, _ = Command(context.Background(), "/usr/bin/killall", "-HUP", "mDNSResponder")
}
func ForeignVPN() bool { c := execPgrep(); return c }
func execPgrep() bool {
	out, e := Command(context.Background(), "/usr/bin/pgrep", "-x", "openconnect")
	return e == nil && strings.TrimSpace(out) != ""
}

func Routes() ([]Route, error) {
	s, e := Command(context.Background(), "/usr/sbin/netstat", "-rn", "-f", "inet")
	if e != nil {
		return nil, e
	}
	return ParseRoutes(s), nil
}
func ParseRoutes(s string) []Route {
	out := []Route{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] == "default" || !policy.ValidInterface(f[3]) {
			continue
		}
		raw, bits, has := strings.Cut(f[0], "/")
		oct := strings.Split(raw, ".")
		if len(oct) > 4 {
			continue
		}
		n := len(oct)
		for len(oct) < 4 {
			oct = append(oct, "0")
		}
		ip, e := netip.ParseAddr(strings.Join(oct, "."))
		if e != nil || !ip.Is4() {
			continue
		}
		length := n * 8
		if strings.Contains(f[2], "H") {
			length = 32
		}
		if has {
			length, e = strconv.Atoi(bits)
			if e != nil || length < 1 || length > 32 {
				continue
			}
		}
		p := netip.PrefixFrom(ip, length).Masked()
		out = append(out, Route{p.String(), f[1], f[3], strings.Contains(f[2], "I"), f[2]})
	}
	return out
}
func RouteArgs(operation string, r Route) ([]string, error) {
	if operation != "add" && operation != "delete" {
		return nil, errors.New("invalid route action")
	}
	p, e := netip.ParsePrefix(r.Prefix)
	if e != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() == 0 || !policy.ValidInterface(r.Interface) {
		return nil, errors.New("invalid owned route")
	}
	mode, target := "-net", p.String()
	if p.Bits() == 32 {
		mode, target = "-host", p.Addr().String()
	}
	args := []string{"-n", operation, mode}
	if r.Scoped {
		if !regexp.MustCompile(`^utun[0-9]+$`).MatchString(r.Interface) {
			return nil, errors.New("VPN route scope required")
		}
		args = append(args, "-ifscope", r.Interface)
	}
	args = append(args, target)
	if r.Scoped {
		args = append(args, "-interface", r.Interface)
	} else {
		if p.Bits() != 32 {
			return nil, errors.New("physical control routes must be exact hosts")
		}
		if _, e := policy.IPv4(r.Gateway); e != nil {
			return nil, e
		}
		args = append(args, r.Gateway, "-ifp", r.Interface)
	}
	return args, nil
}
func MutateRoute(op string, r Route) error {
	a, e := RouteArgs(op, r)
	if e != nil {
		return e
	}
	_, e = Command(context.Background(), "/sbin/route", a...)
	return e
}
func ConfigureVPN(iface, ip string, mtu int) error {
	if !regexp.MustCompile(`^utun[0-9]+$`).MatchString(iface) || mtu < 576 || mtu > 9000 {
		return errors.New("invalid VPN interface configuration")
	}
	if _, e := policy.IPv4(ip); e != nil {
		return e
	}
	_, e := Command(context.Background(), "/sbin/ifconfig", iface, "inet", ip, ip, "netmask", "255.255.255.255", "mtu", strconv.Itoa(mtu), "up")
	return e
}

// CheckConflicts is read-only. It never stops another network manager.
func CheckConflicts(network Network) error {
	out, e := Command(context.Background(), "/usr/sbin/scutil", "--proxy")
	if e != nil {
		return e
	}
	if EnabledProxy(out) {
		return errors.New("another system proxy or PAC is enabled; prepare a network handover before starting")
	}
	out, e = Command(context.Background(), "/usr/sbin/netstat", "-rn", "-f", "inet")
	if e != nil {
		return e
	}
	if HasTunnelDefault(out) {
		return errors.New("another tunnel owns a default route; prepare a network handover before starting")
	}
	return nil
}
func EnabledProxy(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(v) != "1" {
			continue
		}
		switch strings.TrimSpace(k) {
		case "HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable":
			return true
		}
	}
	return false
}
func HasTunnelDefault(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && strings.HasPrefix(f[3], "utun") && (f[0] == "default" || f[0] == "0/1" || f[0] == "128.0/1" || f[0] == "0.0.0.0/1" || f[0] == "128.0.0.0/1") {
			return true
		}
	}
	return false
}
