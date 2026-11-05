//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"netlaunch/internal/securefile"
	"netlaunch/internal/winnet"
	"netlaunch/internal/winstate"
	"netlaunch/internal/winwfp"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type probeDiagnosticEntry string

func (e probeDiagnosticEntry) Name() string      { return string(e) }
func (e probeDiagnosticEntry) IsDir() bool       { return false }
func (e probeDiagnosticEntry) Type() fs.FileMode { return 0 }
func (e probeDiagnosticEntry) Info() (fs.FileInfo, error) {
	return nil, errors.New("fixture does not stat")
}

type probeDiagnosticFixtureStore struct {
	journal    winstate.Journal
	diagnostic func(winstate.Journal) error
	record     func(error)
	saveErr    error
	diagCalls  int
}

func (s *probeDiagnosticFixtureStore) Lock() (func(), error) { return func() {}, nil }
func (s *probeDiagnosticFixtureStore) Load() (winstate.Journal, error) {
	data, err := json.Marshal(s.journal)
	var journal winstate.Journal
	if err == nil {
		err = json.Unmarshal(data, &journal)
	}
	return journal, err
}
func (s *probeDiagnosticFixtureStore) Save(journal winstate.Journal) error {
	return saveProbeJournalWithDiagnostics(journal, func(j winstate.Journal) error {
		if s.saveErr != nil {
			return s.saveErr
		}
		data, err := json.Marshal(j)
		if err == nil {
			err = json.Unmarshal(data, &s.journal)
		}
		return err
	}, func(j winstate.Journal) error {
		s.diagCalls++
		return s.diagnostic(j)
	}, s.record)
}

type probeDiagnosticFixtureBackend struct {
	routes map[winnet.Route]bool
	vpn    winnet.Adapter
	tun    winnet.Adapter
	guard  bool
	trace  []string
}

func (n *probeDiagnosticFixtureBackend) BootID() (string, error) { return "fixture-boot", nil }
func (n *probeDiagnosticFixtureBackend) Lookup(r winnet.Route) (*winnet.Route, error) {
	if n.routes[r] {
		copy := r
		return &copy, nil
	}
	return nil, nil
}
func (n *probeDiagnosticFixtureBackend) Add(r winnet.Route) (winnet.Route, error) {
	return r, errors.New("recovery fixture must not add a route")
}
func (n *probeDiagnosticFixtureBackend) Delete(r winnet.Route) error {
	role := "vpn"
	if r.InterfaceLUID == n.tun.LUID {
		role = "capture"
	}
	n.trace = append(n.trace, role)
	delete(n.routes, r)
	return nil
}
func (n *probeDiagnosticFixtureBackend) Adapter(guid string) (winnet.Adapter, error) {
	for _, adapter := range []winnet.Adapter{n.vpn, n.tun} {
		if adapter.GUID == guid {
			return adapter, nil
		}
	}
	return winnet.Adapter{}, winnet.ErrAdapterAbsent
}
func (n *probeDiagnosticFixtureBackend) DNS(winnet.Adapter, bool) (winnet.DNSSettings, error) {
	return winnet.DNSSettings{}, errors.New("fixture has no DNS changes")
}
func (n *probeDiagnosticFixtureBackend) SetDNS(winnet.Adapter, winnet.DNSSettings) error {
	return errors.New("fixture has no DNS changes")
}
func (n *probeDiagnosticFixtureBackend) InspectGuard(winwfp.Spec) (winwfp.Status, error) {
	return winwfp.Status{Sublayer: n.guard, ForeignApp: n.guard, NonTCP: n.guard, IPv6: n.guard}, nil
}
func (n *probeDiagnosticFixtureBackend) AddGuard(winwfp.Spec) error {
	return errors.New("recovery fixture must not add a guard")
}
func (n *probeDiagnosticFixtureBackend) RemoveGuard(winwfp.Spec) error {
	if len(n.routes) != 0 {
		return errors.New("guard removed before owned routes")
	}
	n.trace = append(n.trace, "guard")
	n.guard = false
	return nil
}

func probeDiagnosticRecoveryFixture(t *testing.T, diagnostic func(winstate.Journal) error, record func(error)) (winstate.Manager, *probeDiagnosticFixtureStore, *probeDiagnosticFixtureBackend) {
	t.Helper()
	vpn := winnet.Adapter{Index: 2, LUID: 22, GUID: "fixture-vpn", Name: "VPN", Type: 53, Up: true}
	tun := winnet.Adapter{Index: 3, LUID: 33, GUID: "fixture-tun", Name: "TUN", Type: 53, Up: true}
	guard, err := winwfp.New(vpn, `C:\fixture\winprobe.exe`, []byte{1, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	vpnRoute, err := winnet.NewRoute(vpn, "192.0.2.2/32", "0.0.0.0", 10)
	if err != nil {
		t.Fatal(err)
	}
	captureRoute, err := winnet.NewRoute(tun, "192.0.2.2/32", "0.0.0.0", 1)
	if err != nil {
		t.Fatal(err)
	}
	s := &probeDiagnosticFixtureStore{diagnostic: diagnostic, record: record, journal: winstate.Journal{
		Version: 1, BootID: "fixture-boot",
		Guards: []winstate.GuardChange{{Spec: guard, State: "applied"}},
		Pairs: []winstate.PairChange{{Guard: guard.Sublayer, TUN: tun,
			VPN: winstate.RouteChange{Route: vpnRoute, State: "applied"}, Capture: winstate.RouteChange{Route: captureRoute, State: "applied"}}},
	}}
	n := &probeDiagnosticFixtureBackend{vpn: vpn, tun: tun, guard: true, routes: map[winnet.Route]bool{vpnRoute: true, captureRoute: true}}
	return winstate.Manager{Store: s, Native: n}, s, n
}

func TestStoppingTransitionDiagnosticsDoNotBlockCleanup(t *testing.T) {
	writeFailure := errors.New("transition write failed")
	for _, scenario := range []string{"corrupt", "write-failure", "over-limit"} {
		t.Run(scenario, func(t *testing.T) {
			files := securefile.AdminStore{Root: filepath.Join("fixture", t.Name())}
			id := "netlaunch-" + strings.Repeat("1", 32)
			markers := map[string][]byte{}
			var nonce byte
			record := func(err error) {
				recordProbeDiagnosticFailureWith(files, id, err, func(path string, value any) error {
					data, err := json.Marshal(value)
					markers[filepath.Base(path)] = data
					return err
				}, func(data []byte) (int, error) { nonce++; data[0] = nonce; return len(data), nil })
			}
			diagnostic := func(j winstate.Journal) error {
				return appendProbeTransitions(j, func() ([]transition, error) {
					if scenario == "over-limit" {
						return make([]transition, 4097), nil
					}
					if scenario == "corrupt" {
						var events []transition
						err := json.Unmarshal([]byte(`{"broken":`), &events)
						return events, err
					}
					return nil, nil
				}, func([]transition) error { return writeFailure })
			}
			manager, store, native := probeDiagnosticRecoveryFixture(t, diagnostic, record)
			if err := manager.Recover(); err != nil {
				t.Fatalf("optional diagnostic blocked owned cleanup: %v", err)
			}
			if !reflect.DeepEqual(native.trace, []string{"vpn", "capture", "guard"}) || len(native.routes) != 0 || native.guard {
				t.Fatalf("cleanup did not complete in order: %#v", native.trace)
			}
			if !store.journal.Stopping || len(markers) == 0 {
				t.Fatal("missing stopping journal or durable diagnostic evidence")
			}
			// Simulate a later process: the durable marker alone must retain failure.
			probeDiagnosticPending.Lock()
			delete(probeDiagnosticPending.errors, probeDiagnosticKey(files, id))
			probeDiagnosticPending.Unlock()
			err := checkProbeDiagnosticFailuresWith(files, id, func() ([]os.DirEntry, error) {
				var entries []os.DirEntry
				for name := range markers {
					entries = append(entries, probeDiagnosticEntry(name))
				}
				return entries, nil
			}, func(path string, _ int64) ([]byte, error) { return markers[filepath.Base(path)], nil })
			if err == nil {
				t.Fatal("diagnostic error must fail final recovery verification after cleanup")
			}
		})
	}
}

func TestStoppingAuthoritativeJournalFailureStillBlocksCleanup(t *testing.T) {
	journalFailure := errors.New("owner network journal save failed")
	manager, store, native := probeDiagnosticRecoveryFixture(t, func(winstate.Journal) error { return nil }, func(error) { t.Fatal("diagnostics must not run") })
	store.saveErr = journalFailure
	if err := manager.Recover(); !errors.Is(err, journalFailure) {
		t.Fatalf("lost authoritative journal error: %v", err)
	}
	if store.diagCalls != 0 || len(native.trace) != 0 || len(native.routes) != 2 || !native.guard {
		t.Fatal("cleanup advanced after authoritative journal save failed")
	}
}

func TestActiveTransitionFailureAndFaultHookAreNotSuppressed(t *testing.T) {
	wanted := errors.New("active transition diagnostic failed")
	j := winstate.Journal{Stopping: false}
	var saved, hook bool
	err := saveProbeJournalWithDiagnostics(j, func(winstate.Journal) error { saved = true; return nil }, func(winstate.Journal) error {
		hook = true
		return wanted
	}, func(error) { t.Fatal("active errors must not become optional") })
	if !saved || !hook || !errors.Is(err, wanted) {
		t.Fatalf("active save/hook semantics changed: %v", err)
	}
}

func TestDiagnosticMarkerWriteFailureRetainedUntilFinalCheck(t *testing.T) {
	files := securefile.AdminStore{Root: filepath.Join("fixture", t.Name())}
	id := "netlaunch-" + strings.Repeat("2", 32)
	writeFailure := errors.New("diagnostic marker write failed")
	recordProbeDiagnosticFailureWith(files, id, errors.New("corrupt transitions"), func(string, any) error {
		return writeFailure
	}, func(data []byte) (int, error) { return len(data), nil })
	err := checkProbeDiagnosticFailuresWith(files, id, func() ([]os.DirEntry, error) { return nil, nil }, func(string, int64) ([]byte, error) {
		t.Fatal("no durable marker was written")
		return nil, nil
	})
	if !errors.Is(err, writeFailure) {
		t.Fatalf("lost diagnostic marker write failure: %v", err)
	}
}
