//go:build darwin

package engine

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
)

func routeFind(wanted platform.Route) (*platform.Route, error) {
	rows, e := platform.Routes()
	if e != nil {
		return nil, e
	}
	var match *platform.Route
	for _, r := range rows {
		if keyMatch(r, wanted) {
			if match != nil {
				return nil, errors.New("ambiguous route identity")
			}
			copy := r
			match = &copy
		}
	}
	return match, nil
}
func ensureRoute(run string, s *State, r platform.Route) error {
	actual, e := routeFind(r)
	if e != nil {
		return e
	}
	if actual != nil {
		for _, owned := range s.Routes {
			if owned.State != "removed" && keyMatch(owned.Route, r) && sameRoute(owned.Route, *actual) {
				return nil
			}
		}
		return errors.New("requested route already exists outside this run")
	}
	i, e := net.InterfaceByName(r.Interface)
	if e != nil {
		return e
	}
	entry := OwnedRoute{r, "planned", i.Index}
	s.Routes = append(s.Routes, entry)
	index := len(s.Routes) - 1
	if e = save(run, s); e != nil {
		return e
	}
	if e = guard(run, s); e != nil {
		return e
	}
	if e = platform.MutateRoute("add", r); e != nil {
		return e
	}
	actual, e = routeFind(r)
	if e != nil || actual == nil || actual.Interface != r.Interface || actual.Scoped != r.Scoped {
		return errors.New("route addition could not be verified")
	}
	if !r.Scoped && actual.Gateway != r.Gateway {
		return errors.New("physical control gateway mismatch")
	}
	s.Routes[index].Route = *actual
	s.Routes[index].State = "applied"
	return save(run, s)
}
func removeRoute(run string, s *State, index int) error {
	entry := s.Routes[index]
	if entry.State == "removed" {
		return nil
	}
	actual, e := routeFind(entry.Route)
	if e != nil {
		return e
	}
	if actual != nil {
		i, e := net.InterfaceByName(entry.Route.Interface)
		if e != nil || i.Index != entry.InterfaceIndex {
			return errors.New("route interface identity changed")
		}
		match := ownedRouteMatches(entry, *actual)
		if !match {
			return errors.New("owned route was externally changed; not deleted")
		}
		if e = platform.MutateRoute("delete", *actual); e != nil {
			return e
		}
		if after, e := routeFind(entry.Route); e != nil || after != nil {
			return errors.New("owned route remains after deletion")
		}
	}
	s.Routes[index].State = "removed"
	return save(run, s)
}
func endpoint(run string, network platform.Network) error {
	return update(run, func(s *State) error {
		if e := guard(run, s); e != nil {
			return e
		}
		r := platform.Route{Prefix: s.Manifest.Config.VPN.EndpointIPv4 + "/32", Gateway: network.Gateway, Interface: network.Interface}
		for i, old := range s.Routes {
			if !old.Route.Scoped && old.State != "removed" && (old.Route.Interface != r.Interface || old.Route.Gateway != r.Gateway) {
				if e := removeRoute(run, s, i); e != nil {
					return e
				}
			}
		}
		return ensureRoute(run, s, r)
	})
}

func hook(run string) error {
	s, e := load(run)
	if e != nil {
		return e
	}
	reason := os.Getenv("reason")
	if reason == "pre-init" {
		return nil
	}
	pid, e := strconv.Atoi(os.Getenv("VPNPID"))
	if e != nil {
		return errors.New("VPN hook PID missing")
	}
	iface := os.Getenv("TUNDEV")
	if iface != s.Manifest.Binding.VPN {
		return errors.New("VPN hook interface mismatch")
	}
	owned := false
	for _, c := range s.Children {
		if c.Role == "vpn" && c.PID == pid {
			ok, e := alive(c)
			if e != nil {
				return e
			}
			owned = ok
		}
	}
	if !owned {
		return errors.New("VPN hook is not from an owned process")
	}
	if reason == "disconnect" || reason == "attempt-reconnect" {
		_ = gate(run)
		return update(run, func(s *State) error {
			s.VPN.Bootstrap = false
			s.Leases = nil
			s.Phase = "reconnecting"
			for i, r := range s.Routes {
				if r.Route.Scoped && r.State != "removed" {
					if e := removeRoute(run, s, i); e != nil {
						return e
					}
				}
			}
			return nil
		})
	}
	if reason != "connect" && reason != "reconnect" {
		return errors.New("unsupported VPN hook reason")
	}
	epoch, e := platform.WakeEpoch()
	if e != nil {
		return e
	}
	ip := os.Getenv("INTERNAL_IP4_ADDRESS")
	if _, e = policy.IPv4(ip); e != nil {
		return e
	}
	mtu := 1412
	if v := os.Getenv("INTERNAL_IP4_MTU"); v != "" {
		mtu, e = strconv.Atoi(v)
		if e != nil {
			return errors.New("invalid VPN MTU")
		}
	}
	_ = gate(run)
	return update(run, func(s *State) error {
		if e := guard(run, s); e != nil {
			return e
		}
		// A fresh generation revokes old route leases before publishing bootstrap.
		for index, route := range s.Routes {
			if route.Route.Scoped && route.State != "removed" {
				if e := removeRoute(run, s, index); e != nil {
					return e
				}
			}
		}
		if e := guard(run, s); e != nil {
			return e
		}
		if e := platform.ConfigureVPN(iface, ip, mtu); e != nil {
			return e
		}
		i, e := net.InterfaceByName(iface)
		if e != nil {
			return e
		}
		s.VPN = VPNSession{PID: pid, Interface: iface, Index: i.Index, Address: ip, Generation: time.Now().UTC().Format(time.RFC3339Nano), WakeEpoch: epoch}
		s.Leases = nil
		for _, dns := range s.Manifest.Config.Company.DNS {
			r := platform.Route{Prefix: dns + "/32", Interface: iface, Scoped: true}
			if e = ensureRoute(run, s, r); e != nil {
				return e
			}
		}
		if current, e := platform.WakeEpoch(); e != nil || current != epoch {
			return errors.New("sleep changed during VPN bootstrap")
		}
		s.VPN.Bootstrap = true
		s.Phase = "connecting"
		return nil
	})
}

func takeoverDNS(run string) error {
	return update(run, func(s *State) error {
		if e := guard(run, s); e != nil {
			return e
		}
		service := s.Manifest.Network.Service
		current, e := platform.DNS(service)
		if e != nil {
			return e
		}
		if old, exists := s.DNS[service]; exists {
			if strings.Join(current, ",") != strings.Join(old.After, ",") && strings.Join(current, ",") != strings.Join(old.Before, ",") {
				return errors.New("system DNS changed outside this run")
			}
		} else {
			s.DNS[service] = DNSChange{current, []string{"127.0.0.1"}}
			if e = save(run, s); e != nil {
				return e
			}
		}
		if e = guard(run, s); e != nil {
			return e
		}
		if e = platform.SetDNS(service, []string{"127.0.0.1"}); e != nil {
			return e
		}
		current, e = platform.DNS(service)
		if e != nil || strings.Join(current, ",") != "127.0.0.1" {
			return errors.New("local DNS takeover failed")
		}
		platform.FlushDNS()
		return nil
	})
}

func validVPN(s State) bool {
	epoch, e := platform.WakeEpoch()
	if e != nil || s.VPN.WakeEpoch == "" || epoch != s.VPN.WakeEpoch {
		return false
	}
	i, e := net.InterfaceByName(s.VPN.Interface)
	if e != nil || i.Index != s.VPN.Index || i.Flags&net.FlagUp == 0 {
		return false
	}
	addrs, _ := i.Addrs()
	for _, raw := range addrs {
		p, e := netip.ParsePrefix(raw.String())
		if e == nil && p.Addr().String() == s.VPN.Address {
			return true
		}
	}
	return false
}

func saveCore(run string, config any) error {
	return securefile.Write(filepath.Join(private(run), "core.json"), config)
}

func readCore(run string, v any) error { return readJSON(filepath.Join(private(run), "core.json"), v) }
