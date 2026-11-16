//go:build windows

package engine

import (
	"testing"
	"time"

	"netlaunch/internal/personalroute"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/winnet"
)

func TestDesktopFallbackRequiresNewCurrentProof(t *testing.T) {
	now := time.Unix(1000, 0)
	proof := now.Add(25 * time.Second)
	validation := now.Add(20 * time.Second)
	allFailed := personalroute.Decision{DirectAllowed: true, Reason: personalroute.ReasonAllFailed, ExpiresAt: proof}
	manual := personalroute.Decision{DirectAllowed: true, Reason: personalroute.ReasonManualDisabled}
	if got := desktopFallbackDeadline(manual, validation, now); !got.IsZero() {
		t.Fatal("manual Personal off authorized an automatic lease")
	}
	if got := desktopFallbackDeadline(allFailed, validation, validation); !got.IsZero() {
		t.Fatal("expired run authorized an automatic lease")
	}
	if got := desktopFallbackDeadline(allFailed, validation, now); !got.Equal(validation) {
		t.Fatalf("the lease exceeded the validation deadline: %v", got)
	}

	var lease desktopFallbackLease
	if op, ok := lease.next(proof); !ok || op != openFallbackLease {
		t.Fatal("fresh evidence did not attempt to open a lease")
	}
	lease.until = proof.Add(-time.Second)
	if _, ok := lease.next(proof); ok {
		t.Fatal("the shorter core cutoff allowed renewal with the same proof")
	}
	if lease.shouldWithdraw(proof, now) || !lease.shouldWithdraw(now, now) {
		t.Fatal("active proof was not distinguished from shortened or withdrawn proof")
	}

	fresh := proof.Add(3 * time.Second)
	if op, ok := lease.next(fresh); !ok || op != renewFallbackLease {
		t.Fatal("newer evidence did not attempt to renew the live lease")
	}
	if !lease.shouldWithdraw(fresh, lease.until) {
		t.Fatal("local expiry of the core lease did not force withdrawal")
	}
	// A failed renewal withdraws the gate but retains the attempted proof.
	lease.until = time.Time{}
	if _, ok := lease.next(fresh); ok {
		t.Fatal("the same proof reopened an expired or rejected lease")
	}
	if op, ok := lease.next(fresh.Add(time.Second)); !ok || op != openFallbackLease {
		t.Fatal("fresh proof could not open a new lease after revocation")
	}
}

func TestDesktopFallbackScopeBindsAppliedRunAndPhysicalNetwork(t *testing.T) {
	intent := policy.ChannelIntent{Company: true, Personal: true, Environment: "office"}
	state := func() State {
		return State{
			DesiredChannels: &intent, ChannelGeneration: 2,
			AppliedChannels: &intent, AppliedGeneration: 2, TakeoverActive: true, RunSpecDigest: "frozen-run",
			Runner: platform.Identity{PID: 1, Birth: "creation", Executable: "netlaunch.exe", OwnerSID: "owner"},
			Windows: &WindowsState{
				BootID: "boot", PublicRun: "run", Epoch: 3, ValidationDeadline: time.Unix(1000, 0),
				Physical: winnet.Physical{Adapter: winnet.Adapter{GUID: "nic", Index: 4, LUID: 5}, Address: "192.0.2.10", Gateway: "192.0.2.1"},
			},
		}
	}
	if !sameDesktopFallbackScope(state(), state()) {
		t.Fatal("matching applied desktop state rejected the exact proof scope")
	}
	for _, tt := range []struct {
		name   string
		mutate func(*State)
	}{
		{"reused_process", func(s *State) { s.Runner.Birth = "new-process" }},
		{"replacement_run", func(s *State) { s.Windows.PublicRun = "new-run" }},
		{"different_boot", func(s *State) { s.Windows.BootID = "new-boot" }},
		{"different_profile", func(s *State) { s.RunSpecDigest = "new-spec" }},
		{"wake", func(s *State) { s.Windows.Epoch++ }},
		{"reused_adapter_index", func(s *State) { s.Windows.Physical.Adapter.LUID++ }},
		{"new_address", func(s *State) { s.Windows.Physical.Address = "192.0.2.11" }},
		{"gateway", func(s *State) { s.Windows.Physical.Gateway = "192.0.2.2" }},
		{"validation_deadline", func(s *State) { s.Windows.ValidationDeadline = s.Windows.ValidationDeadline.Add(time.Second) }},
		{"new_intent_generation", func(s *State) { s.ChannelGeneration++; s.AppliedGeneration++ }},
		{"pending_intent_generation", func(s *State) { s.ChannelGeneration++ }},
		{"not_applied", func(s *State) { s.AppliedChannels = nil }},
		{"stopped_takeover", func(s *State) { s.TakeoverActive = false }},
		{"personal_off", func(s *State) {
			off := intent
			off.Personal = false
			s.DesiredChannels, s.AppliedChannels = &off, &off
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			changed := state()
			tt.mutate(&changed)
			if sameDesktopFallbackScope(state(), changed) {
				t.Fatal("accepted evidence for invalidated scope")
			}
		})
	}
}
