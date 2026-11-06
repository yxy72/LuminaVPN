//go:build windows

package engine

import (
	"errors"
	"testing"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/winnet"
	"netlaunch/internal/winstate"
	"netlaunch/internal/winwfp"
)

func serviceProofFixture() (State, winstate.Journal, serviceProofNative) {
	id := func(pid int) platform.Identity {
		return platform.Identity{PID: pid, Birth: "fixed-birth", Executable: `C:\protected\netlaunch.exe`, OwnerSID: "S-1-5-18"}
	}
	a := winnet.Adapter{Index: 43, LUID: 12345, GUID: "{8B3AFCE7-975C-4164-A9B1-6B9BFBB4D032}", Name: "NL-TUN-fixture", Type: 53}
	core := id(44)
	guard, err := winwfp.New(a, `C:\protected\netlaunch.exe`, []byte{1, 2, 3, 4})
	if err != nil {
		panic(err)
	}
	ipv6, err := winwfp.NewIPv6()
	if err != nil {
		panic(err)
	}
	s := State{Phase: "stopped", Runner: id(42), Watcher: id(43), Children: []Child{{Role: "core", Native: &core}}, Windows: &WindowsState{AdapterIntents: []OwnedAdapterIntent{{Role: "core", Name: a.Name, Owner: core, Adapter: &a}}}}
	j := winstate.Journal{Version: 1, BootID: "fixture-boot", Stopping: true, Routes: []winstate.RouteChange{{State: "restored", Route: winnet.Route{InterfaceIndex: 43, InterfaceLUID: 12345, Prefix: "0.0.0.0/1", NextHop: "0.0.0.0", Metric: 317}}}, DNS: []winstate.DNSChange{{State: "restored", Before: winnet.DNSSettings{NameServers: "1.1.1.1"}, After: winnet.DNSSettings{NameServers: "127.0.0.1"}}}, Guards: []winstate.GuardChange{{Spec: guard, State: "restored"}}, IPv6Guards: []winstate.IPv6GuardChange{{Spec: ipv6, State: "restored"}}}
	n := serviceProofNative{
		presence: func(a winnet.Adapter) (winnet.AdapterPresence, error) {
			return winnet.AdapterPresence{State: "absent", Expected: a}, nil
		},
		process: func(int) (platform.Identity, error) { return platform.Identity{}, nil },
		route:   func(winnet.Route) (*winnet.Route, error) { return nil, nil },
		dns:     func(winnet.Adapter, bool) (winnet.DNSSettings, error) { return j.DNS[0].Before, nil },
		guard:   func(winwfp.Spec) (winwfp.Status, error) { return winwfp.Status{}, nil },
		ipv6:    func(winwfp.IPv6Spec) (winwfp.IPv6Status, error) { return winwfp.IPv6Status{}, nil },
	}
	return s, j, n
}
func TestServiceRecoveryRequiresEveryNativeProof(t *testing.T) {
	s, j, n := serviceProofFixture()
	if p := observeServiceRecovery(s, j, n); !p.Clean || len(p.Adapters) != 1 || len(p.Processes) != 3 {
		t.Fatal("complete proof rejected", p)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*State, *winstate.Journal, *serviceProofNative)
	}{
		{"unpublished_identity", func(s *State, j *winstate.Journal, n *serviceProofNative) { s.Windows.AdapterIntents[0].Adapter = nil }},
		{"inactive_adapter_still_present", func(s *State, j *winstate.Journal, n *serviceProofNative) {
			n.presence = func(a winnet.Adapter) (winnet.AdapterPresence, error) {
				a.Up = false
				return winnet.AdapterPresence{State: "present", Expected: a}, nil
			}
		}},
		{"adapter_unknown", func(s *State, j *winstate.Journal, n *serviceProofNative) {
			n.presence = func(a winnet.Adapter) (winnet.AdapterPresence, error) {
				return winnet.AdapterPresence{State: "unknown"}, errors.New("query unavailable")
			}
		}},
		{"process_access_denied", func(s *State, j *winstate.Journal, n *serviceProofNative) {
			n.process = func(int) (platform.Identity, error) { return platform.Identity{}, errors.New("access denied") }
		}},
		{"exact_process_alive", func(s *State, j *winstate.Journal, n *serviceProofNative) {
			n.process = func(pid int) (platform.Identity, error) { id := s.Runner; id.PID = pid; return id, nil }
		}},
		{"route_residual", func(s *State, j *winstate.Journal, n *serviceProofNative) {
			n.route = func(r winnet.Route) (*winnet.Route, error) { return &r, nil }
		}},
		{"dns_changed", func(s *State, j *winstate.Journal, n *serviceProofNative) {
			n.dns = func(winnet.Adapter, bool) (winnet.DNSSettings, error) {
				return winnet.DNSSettings{NameServers: "8.8.8.8"}, nil
			}
		}},
		{"wfp_residual", func(s *State, j *winstate.Journal, n *serviceProofNative) {
			n.guard = func(winwfp.Spec) (winwfp.Status, error) { return winwfp.Status{Sublayer: true}, nil }
		}},
		{"ipv6_unknown", func(s *State, j *winstate.Journal, n *serviceProofNative) {
			n.ipv6 = func(winwfp.IPv6Spec) (winwfp.IPv6Status, error) { return winwfp.IPv6Status{}, errors.New("unknown") }
		}},
		{"journal_not_terminal", func(s *State, j *winstate.Journal, n *serviceProofNative) { j.Routes[0].State = "applied" }},
		{"status_only_is_not_cleanup", func(s *State, j *winstate.Journal, n *serviceProofNative) { s.TakeoverActive = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, j, n := serviceProofFixture()
			tc.mutate(&s, &j, &n)
			if p := observeServiceRecovery(s, j, n); p.Clean {
				t.Fatal("incomplete native evidence accepted", p)
			}
		})
	}
}
func TestServiceModeBindingCannotRenewOrChangeOwner(t *testing.T) {
	now := time.Unix(1700000000, 0)
	b := ServiceRunBinding{ProfileID: "profile-fixture", RunRef: "run-reference", ServiceInstance: "service-instance", CallerSID: "S-1-5-21-1-2-3-1001", LogonSID: "S-1-5-5-1-2", AuthenticationID: "00000000-00000001", SessionID: 1, ExecutorSID: "S-1-5-18", Revision: 1, Deadline: now.Add(45 * time.Minute)}
	b.ServiceHost = platform.Identity{PID: 51, Birth: "host-birth", OwnerSID: "S-1-5-18", Executable: `C:\Program Files\LuminaVPN\releases\fixture\lumina-service.exe`}
	b.ServiceHostSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := b.Validate(Validation, now); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*ServiceRunBinding){func(b *ServiceRunBinding) { b.Deadline = b.Deadline.Add(time.Nanosecond) }, func(b *ServiceRunBinding) { b.ProfileID = "../user-runtime" }, func(b *ServiceRunBinding) { b.ExecutorSID = b.CallerSID }, func(b *ServiceRunBinding) { b.CallerSID = "S-1-5-18" }, func(b *ServiceRunBinding) { b.SessionID = 0 }} {
		bad := b
		change(&bad)
		if bad.Validate(Validation, now) == nil {
			t.Fatal("unsafe service binding accepted")
		}
	}
	if b.Validate(Daily, now) == nil {
		t.Fatal("daily inherited a validation deadline")
	}
	b.Deadline = time.Time{}
	if !platform.WindowsClientValidationOnly && b.Validate(Daily, now) != nil {
		t.Fatal("explicit daily rejected")
	}
	if platform.WindowsClientValidationOnly && b.Validate(Daily, now) == nil {
		t.Fatal("validation-only service accepted daily")
	}
}
