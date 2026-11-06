//go:build windows

package engine

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/winnet"
	"netlaunch/internal/winwfp"
	"os"
	"strconv"
)

const windowsFlowIsolationReady = platform.WindowsValidationBuild || platform.WindowsHomeBuild || platform.WindowsClientBuild

var windowsPower *winnet.PowerWatch // Set once, before company workers start.
func validVPN(s State) bool {
	return validateVPN(s) == nil
}
func validateVPN(s State) error {
	if !currentIntent(s).Company {
		return errors.New("company channel is disabled")
	}
	if windowsPower == nil || s.Windows == nil || !s.VPN.Bootstrap {
		return errors.New("VPN bootstrap is not active")
	}
	epoch, awake := windowsPower.Epoch()
	if !awake || epoch != s.Windows.Epoch {
		return errors.New("VPN power epoch changed")
	}
	if e := winnet.ValidateAdapter(s.Windows.VPNAdapter, s.VPN.Address); e != nil {
		return fmt.Errorf("VPN adapter validation: %w", e)
	}
	if s.Windows.Guard == nil || !winnet.SameAdapter(s.Windows.Guard.Adapter, s.Windows.VPNAdapter) {
		return errors.New("VPN isolation adapter differs")
	}
	m, e := networkManager(s.Windows.PublicRun)
	if e != nil {
		return e
	}
	if e = m.CheckCompanyGuard(*s.Windows.Guard); e != nil {
		return fmt.Errorf("VPN isolation readback: %w", e)
	}
	return winnet.AddressReady(s.Windows.VPNAddress)
}
func takeoverDNS(run string) error {
	return update(run, func(s *State) error {
		if e := s.Manifest.ValidateMode(); e != nil {
			return e
		}
		if e := guard(run, s); e != nil {
			return e
		}
		m, e := networkManager(run)
		if e != nil {
			return e
		}
		// Each family has its own durable intent, so a crash between the two
		// native calls can restore either family without overwriting the other.
		if e = m.SetDNS(s.Windows.Physical.Adapter, winnet.DNSSettings{NameServers: "127.0.0.1"}); e != nil {
			return e
		}
		return m.SetDNS(s.Windows.Physical.Adapter, winnet.DNSSettings{IPv6: true, NameServers: "::1"})
	})
}
func hook(run string) (returned error) {
	stage := "authorize"
	defer func() {
		if returned == nil {
			return
		}
		returned = fmt.Errorf("VPN callback %s: %w", stage, returned)
		// Script-host stderr is not reliably inherited by OpenConnect. Keep
		// the failure in protected storage without logging callback environment
		// variables, which include the launch capability and VPN parameters.
		if log, err := privateLog(run, "hook"); err == nil {
			_, _ = fmt.Fprintln(log, returned)
			_ = log.Close()
		}
	}()
	token := os.Getenv("NETLAUNCH_HOOK_TOKEN")
	return update(run, func(s *State) error {
		if e := guard(run, s); e != nil {
			return e
		}
		if len(token) != 64 || subtle.ConstantTimeCompare([]byte(token), []byte(s.Windows.LaunchToken)) != 1 {
			return errors.New("stale or unowned VPN callback")
		}
		owned := false
		for _, c := range s.Children {
			if c.Role == "vpn" {
				ok, e := alive(c)
				if e != nil {
					return e
				}
				owned = owned || ok
			}
		}
		if !owned {
			return errors.New("VPN callback owner is not alive")
		}
		reason := os.Getenv("reason")
		switch reason {
		case "pre-init":
			return nil
		case "disconnect", "attempt-reconnect":
			s.VPN.Bootstrap = false
			s.Leases = nil
			s.Phase = "reconnecting"
			return nil
		case "connect", "reconnect":
		default:
			return errors.New("unsupported VPN callback reason")
		}
		name := os.Getenv("TUNDEV")
		stage = "interface_parameters"
		if name != s.Manifest.Binding.VPN {
			return errors.New("VPN callback interface differs")
		}
		index, e := strconv.ParseUint(os.Getenv("TUNIDX"), 10, 32)
		if e != nil || index == 0 {
			return errors.New("VPN callback lacks native index")
		}
		ip := os.Getenv("INTERNAL_IP4_ADDRESS")
		if _, e = policy.IPv4(ip); e != nil {
			return e
		}
		mtu := uint64(1412)
		if raw := os.Getenv("INTERNAL_IP4_MTU"); raw != "" {
			mtu, e = strconv.ParseUint(raw, 10, 32)
			if e != nil {
				return errors.New("invalid VPN MTU")
			}
		}
		if !winnet.ValidVPNMTU(uint32(mtu)) {
			return errors.New("VPN MTU outside supported range")
		}
		stage = "adapter_identity"
		all, e := winnet.Adapters()
		if e != nil {
			return e
		}
		var adapter winnet.Adapter
		for _, a := range all {
			if a.Index == uint32(index) && a.Name == name && a.Type == 53 && !a.Hardware {
				adapter = a
			}
		}
		if adapter.GUID == "" {
			return errors.New("new virtual VPN adapter not found")
		}
		for _, before := range s.Windows.AdapterBefore {
			if before == adapter.GUID {
				return errors.New("VPN callback selected a pre-existing adapter")
			}
		}
		if s.Manifest.Service != nil {
			if e = bindOwnedAdapterIntent(s, "vpn", adapter); e != nil {
				return e
			}
			if e = save(run, s); e != nil {
				return e
			}
		}
		stage = "isolation"
		m, e := networkManager(run)
		if e != nil {
			return e
		}
		runner, e := platform.Process(s.Runner.PID)
		if e != nil {
			return e
		}
		if e = verifyFrozenRunner(run, *s, runner); e != nil {
			return e
		}
		tun, e := findCandidate(s.Manifest.Binding.TUN, s.Windows.AdapterBefore)
		if e != nil {
			return e
		}
		if !winnet.SameAdapter(tun, s.Windows.TUNAdapter) {
			return errors.New("core TUN changed before VPN bootstrap")
		}
		var spec winwfp.Spec
		if s.Windows.Guard != nil {
			if !winnet.SameAdapter(s.Windows.Guard.Adapter, adapter) {
				return errors.New("previous VPN isolation needs recovery")
			}
			spec = *s.Windows.Guard
		} else {
			spec, e = winwfp.Prepare(adapter, s.Manifest.Executable)
			if e != nil {
				return e
			}
		}
		if e = m.EnsureGuard(spec); e != nil {
			return e
		}
		stage = "address"
		address, e := m.EnsureVPNAddress(adapter, ip)
		if e != nil {
			return e
		}
		stage = "mtu"
		if e = m.SetVPNMTU(adapter, uint32(mtu)); e != nil {
			return e
		}
		stage = "resolver_routes"
		for _, dns := range s.Manifest.Config.Company.DNS {
			if e = m.EnsureCompanyRoute(spec, tun, dns+"/32"); e != nil {
				return e
			}
		}
		s.Windows.Guard = &spec
		// No server-pushed route, DNS server or search suffix is ever applied.
		s.Windows.VPNAdapter = adapter
		s.Windows.VPNAddress = address
		s.VPN = VPNSession{Interface: name, Index: int(adapter.Index), Address: ip, Generation: token, Bootstrap: true}
		s.Leases = nil
		s.Phase = "connecting"
		return nil
	})
}
func findCandidate(name string, before []string) (winnet.Adapter, error) {
	all, e := winnet.Adapters()
	if e != nil {
		return winnet.Adapter{}, e
	}
	for _, a := range all {
		if a.Name != name || a.Hardware || a.Type != 53 || !a.Up {
			continue
		}
		for _, old := range before {
			if a.GUID == old {
				return winnet.Adapter{}, errors.New("candidate existed before this run")
			}
		}
		return a, nil
	}
	return winnet.Adapter{}, errors.New("candidate adapter not ready")
}

// discoverTUN records the bare core adapter before any company route exists.
func discoverTUN(run string) error {
	return update(run, func(s *State) error {
		if e := guard(run, s); e != nil {
			return e
		}
		a, e := findCandidate(s.Manifest.Binding.TUN, s.Windows.AdapterBefore)
		if e != nil {
			return e
		}
		s.Windows.TUNAdapter = a
		if s.Manifest.Service != nil {
			return bindOwnedAdapterIntent(s, "core", a)
		}
		return nil
	})
}
func capture(run string) error {
	return update(run, func(s *State) error {
		if e := guard(run, s); e != nil {
			return e
		}
		a, e := findCandidate(s.Manifest.Binding.TUN, s.Windows.AdapterBefore)
		if e != nil {
			return e
		}
		if !winnet.SameAdapter(s.Windows.TUNAdapter, a) {
			return errors.New("core TUN identity changed")
		}
		m, e := networkManager(run)
		if e != nil {
			return e
		}
		for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			r, e := winnet.NewCaptureRoute(a, prefix)
			if e != nil {
				return e
			}
			if e = m.EnsureRoute(r); e != nil {
				return e
			}
		}
		return nil
	})
}
func endpoint(run string, physical winnet.Physical) error {
	return update(run, func(s *State) error {
		if e := guard(run, s); e != nil {
			return e
		}
		if e := winnet.ValidateAdapter(physical.Adapter, physical.Address); e != nil {
			return e
		}
		m, e := networkManager(run)
		if e != nil {
			return e
		}
		journal, e := m.Store.Load()
		if e != nil {
			return e
		}
		prefix := s.Manifest.Config.VPN.EndpointIPv4 + "/32"
		wanted, e := winnet.NewRoute(physical.Adapter, prefix, physical.Gateway, 317)
		if e != nil {
			return e
		}
		for _, entry := range journal.Routes {
			r := entry.Route
			if entry.State != "restored" && r.Prefix == prefix && r.NextHop != "0.0.0.0" && !winnet.OwnedEqual(r, wanted) {
				if e = m.RemoveRoute(r); e != nil {
					return e
				}
			}
		}
		if e = m.EnsureRoute(wanted); e != nil {
			return e
		}
		s.Windows.Physical = physical
		return nil
	})
}
func freshEpoch(run string) error {
	epoch, awake := windowsPower.Epoch()
	if !awake {
		return errors.New("computer is suspended")
	}
	return update(run, func(s *State) error {
		if e := guard(run, s); e != nil {
			return e
		}
		s.Windows.Epoch = epoch
		s.VPN.Bootstrap = false
		s.Leases = nil
		s.Phase = "reconnecting"
		return nil
	})
}
