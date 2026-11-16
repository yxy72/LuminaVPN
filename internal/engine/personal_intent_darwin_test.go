//go:build darwin

package engine

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/selector"
	"netlaunch/internal/testutil"
)

func personalChangeFixture(t *testing.T, personal bool) State {
	t.Helper()
	s := companyTransitionFixture(t, true)
	intent := currentIntent(s)
	intent.Personal = personal
	s.Manifest.Channels, s.DesiredChannels, s.AppliedChannels = &intent, &intent, &intent
	s.DarwinPersonal = &darwinPersonalControl{}
	if !personal {
		s.Personal = "PHYSICAL"
	}
	return s
}

func TestDarwinFrozenPersonalPoolIsOptionalWhenInitiallyOff(t *testing.T) {
	run := testutil.PrivateTempDir(t)
	state := personalChangeFixture(t, false)
	if nodes := frozenDarwinPersonalPool(run, state.Manifest, nil); len(nodes) != 0 {
		t.Fatal("missing optional personal pool was enabled")
	}
	nodes := []policy.Node{{"type": "hysteria2", "server": "203.0.113.30", "port": 443, "password": "fixture-only"}}
	if err := securefile.Write(filepath.Join(run, "nodes.json"), nodes); err != nil {
		t.Fatal(err)
	}
	found := frozenDarwinPersonalPool(run, state.Manifest, nil)
	if len(found) != 1 || found[0]["name"] != "P001" || currentIntent(state).Personal {
		t.Fatalf("optional candidate changed startup intent: %v", len(found))
	}
	state.Manifest.Config.Personal.DNS = nil
	if nodes := frozenDarwinPersonalPool(run, state.Manifest, nil); len(nodes) != 0 {
		t.Fatal("incomplete personal resolver policy advertised a frozen pool")
	}
}

func TestDarwinPersonalIntentOffOnPublishesOneGenerationAndPreservesCompany(t *testing.T) {
	s := personalChangeFixture(t, true)
	s.VPN.Bootstrap = true
	s.Children = []Child{{Role: "vpn", PID: 12, Released: true}}
	for _, want := range []bool{false, true} {
		id := "off"
		if want {
			id = "on"
		}
		r := DarwinDesktopPersonalRequest{ID: id, Generation: s.ChannelGeneration, Company: true, Personal: want, Inode: 1}
		old := currentIntent(s)
		if err := queueDarwinPersonalChange(&s, r); err != nil {
			t.Fatal(err)
		}
		if currentIntent(s) != old || s.ChannelGeneration != r.Generation ||
			publicStatus(s, time.Now()).DarwinPersonalControl || publicStatus(s, time.Now()).DarwinCompanyControl {
			t.Fatal("queued personal change altered live intent or allowed competing control")
		}
		if done, err := darwinDesktopPersonalApplied(s, r); done || err != nil {
			t.Fatal("request acknowledged without native readback", err)
		}
		change, err := pendingDarwinPersonalChange(s)
		if err != nil {
			t.Fatal(err)
		}
		var selected []string
		verify := func(seen State) error {
			current, err := pendingDarwinPersonalChange(seen)
			if err != nil || current != change {
				return errors.New("stale transition")
			}
			return nil
		}
		err = change.publish(&s, verify, func(group, target string) error {
			if currentIntent(s) != old || s.AppliedGeneration != r.Generation {
				t.Fatal("intent published before native selector readback")
			}
			selected = append(selected, group+"="+target)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{"PHYSICAL=PHYSICAL-BOUND"}
		route := selector.Reject
		if !want {
			expected = append(expected, "PERSONAL=PHYSICAL")
			route = "PHYSICAL"
		}
		if !reflect.DeepEqual(selected, expected) || s.Personal != route || s.PersonalFallback ||
			!s.VPN.Bootstrap || s.Children[0].DarwinVPNRetired || !s.AppliedChannels.Company ||
			s.AppliedChannels.Environment != old.Environment || s.ChannelGeneration != r.Generation+1 {
			t.Fatal("unexpected committed route or mutated Company intent", selected, s.Personal, s.AppliedChannels)
		}
		if done, err := darwinDesktopPersonalApplied(s, r); !done || err != nil {
			t.Fatal("protected native receipt failed", err)
		}
		if again := queueDarwinPersonalChange(&s, r); again != nil || s.DarwinPersonal.Pending {
			t.Fatal("a replay requeued a completed request")
		}
	}
}

func TestDarwinPersonalTransitionRejectsConflictingIntentAndCanceledReadback(t *testing.T) {
	s := personalChangeFixture(t, true)
	off := DarwinDesktopPersonalRequest{ID: "off", Generation: 1, Company: true, Inode: 1}
	wrongCompany := off
	wrongCompany.Company = false
	if queueDarwinPersonalChange(&s, wrongCompany) == nil {
		t.Fatal("personal request accepted a changed Company intent")
	}
	if err := queueDarwinCompanyChange(&s, "company", 1, false); err != nil {
		t.Fatal(err)
	}
	if queueDarwinPersonalChange(&s, off) == nil {
		t.Fatal("personal ran while Company mutation was pending")
	}
	s.DarwinCompany = &darwinCompanyControl{}
	if err := queueDarwinPersonalChange(&s, off); err != nil {
		t.Fatal(err)
	}
	if queueDarwinCompanyChange(&s, "company", 1, false) == nil {
		t.Fatal("Company ran while personal mutation was pending")
	}
	change, err := pendingDarwinPersonalChange(s)
	if err != nil {
		t.Fatal(err)
	}
	opened := 0
	err = change.publish(&s, func(State) error {
		if opened == 1 {
			return errDarwinPersonalRequestCanceled
		}
		return nil
	}, func(group, target string) error {
		opened++
		return nil
	})
	if !errors.Is(err, errDarwinPersonalRequestCanceled) || opened != 1 || s.AppliedGeneration != 1 ||
		!s.DarwinPersonal.Pending || !s.AppliedChannels.Personal || s.Personal == "PHYSICAL" {
		t.Fatal("a canceled readback published direct", err, opened, s.AppliedGeneration)
	}
	if done, err := darwinDesktopPersonalApplied(s, off); done || err != nil {
		t.Fatal("the interrupted generation acknowledged success", err)
	}
	s.DarwinPersonal = nil
	if queueDarwinPersonalChange(&s, off) == nil {
		t.Fatal("a run without frozen candidates accepted a personal request")
	}
}
