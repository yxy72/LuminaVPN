//go:build darwin

package engine

import (
	"context"
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
		if !currentIntent(*s).Company {
			return errors.New("macOS company channel is disabled")
		}
		r := platform.Route{Prefix: s.Manifest.Config.VPN.EndpointIPv4 + "/32", Gateway: network.Gateway, Interface: network.Interface}
		for i, old := range s.Routes {
			if !old.Route.Scoped && old.Route.Prefix == r.Prefix && old.State != "removed" &&
				(old.Route.Interface != r.Interface || old.Route.Gateway != r.Gateway) {
				if e := removeRoute(run, s, i); e != nil {
					return e
				}
			}
		}
		return ensureRoute(run, s, r)
	})
}

func rebindDarwinVPNEndpoint(run string, s State, network platform.Network) error {
	child, found := latestVPN(s)
	if !found || !child.Released || child.DarwinVPNRetired {
		return nil
	}
	ok, err := alive(child)
	if err != nil || !ok {
		return err
	}
	return endpoint(run, network)
}

func retireDarwinCompanyRoutes(s *State, remove func(int) error) error {
	endpoint := s.Manifest.Config.VPN.EndpointIPv4 + "/32"
	for i := len(s.Routes) - 1; i >= 0; i-- {
		route := s.Routes[i]
		if route.State == "removed" || (!route.Route.Scoped && route.Route.Prefix != endpoint) {
			continue
		}
		if err := remove(i); err != nil {
			return err
		}
	}
	return nil
}

func hook(run string) error {
	reason := os.Getenv("reason")
	if reason == "pre-init" {
		s, err := load(run)
		if err != nil {
			return err
		}
		if !currentIntent(s).Company {
			return errors.New("macOS company channel is disabled")
		}
		return guard(run, &s)
	}
	pid, e := strconv.Atoi(os.Getenv("VPNPID"))
	if e != nil || pid < 2 {
		return errors.New("VPN hook PID missing")
	}
	iface := os.Getenv("TUNDEV")
	if reason == "disconnect" || reason == "attempt-reconnect" {
		return applyDarwinVPNHook(run, pid, iface, func(s *State) error {
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
	return applyDarwinVPNHook(run, pid, iface, func(s *State) error {
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
		if e := guard(run, s); e != nil {
			return e
		}
		s.VPN.Bootstrap = true
		s.Phase = "connecting"
		return nil
	})
}

func applyDarwinVPNHook(run string, pid int, iface string, change func(*State) error) error {
	return update(run, func(s *State) error {
		if err := guard(run, s); err != nil {
			return err
		}
		if err := requireActiveDarwinOwner(run, *s); err != nil {
			return err
		}
		if err := validateDarwinVPNHook(*s, pid, iface, platform.Process); err != nil {
			return err
		}
		// All hook mutations, including closing the gate, follow validation of
		// the current attempt while holding state.lock.
		if err := fenceDarwinCompanyTraffic(s, func() error { return save(run, s) }, func() error { return closeDarwinCompanyGate(run, *s) }); err != nil {
			return err
		}
		if err := guard(run, s); err != nil {
			return err
		}
		return change(s)
	})
}

func validateDarwinVPNHook(s State, pid int, iface string, process func(int) (platform.Identity, error)) error {
	if !currentIntent(s).Company {
		return errors.New("macOS company channel is disabled")
	}
	if iface == "" || iface != s.Manifest.Binding.VPN {
		return errors.New("VPN hook interface mismatch")
	}
	child, found := latestVPN(s)
	if !found || !child.Released || child.DarwinVPNRetired || pid != child.PID || len(child.Args) == 0 {
		return errors.New("VPN hook is not from the current attempt")
	}
	id, err := process(pid)
	if err != nil {
		return err
	}
	if id.PID != pid || id.Birth != child.Birth || id.Executable != child.Args[0] || id.Command != strings.Join(child.Args, " ") {
		return errors.New("VPN hook process identity mismatch")
	}
	return nil
}

func retireDarwinVPNAttempt(s *State) {
	for i := len(s.Children) - 1; i >= 0; i-- {
		if s.Children[i].Role == "vpn" {
			s.Children[i].DarwinVPNRetired = true
			return
		}
	}
}

func revokeDarwinCompanyState(s *State) {
	s.VPN.Bootstrap = false
	s.Leases = nil
	delete(s.Channels, "company")
}

func fenceDarwinCompanyTraffic(s *State, persist, closeGate func() error) error {
	revokeDarwinCompanyState(s)
	// Persist the revoked authority before contacting the core so the bound
	// ingress rejects new dials even if the controller does not acknowledge.
	if err := persist(); err != nil {
		return err
	}
	return closeGate()
}

func closeDarwinCompanyGate(run string, s State) error {
	for i := len(s.Children) - 1; i >= 0; i-- {
		c := s.Children[i]
		if c.Role != "core" || !c.Released {
			continue
		}
		ok, err := alive(c)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("owned core unavailable during company gate closure")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return selectCoreGroupContext(ctx, run, "CORP", "REJECT")
	}
	// The first VPN bootstrap can occur before the core is released. Its
	// configuration starts with the company gate closed.
	return nil
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
	if !currentIntent(s).Company {
		return false
	}
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
