//go:build darwin || windows

package engine

import (
	"context"
	"errors"
	"time"

	"netlaunch/internal/policy"
	"netlaunch/internal/selector"
)

// A batch aggregates every configured target before publishing channel health.
// One successful target cannot erase another target's failure in that channel.
func checkSystemChannels(ctx context.Context, run string, probes []policy.Probe, selection *selector.Policy, authorized, skipCompany bool) (bool, error) {
	before, err := load(run)
	if err != nil {
		return false, err
	}
	checks := map[string]ChannelHealth{}
	if selection.Current == selector.Reject {
		// A deliberately closed ingress cannot verify the system path. Preserve
		// its actionable failure instead of replacing a service error with the
		// connection failure caused by our own REJECT gate.
		h := before.Channels["personal"]
		h.ChannelStatus = channelView(before, "personal", time.Now())
		if h.State == "ready" {
			h.ChannelStatus = ChannelStatus{State: "unavailable", Reason: "no_verified_node", NextAction: "wait_for_selection"}
		}
		h.Node = selector.Reject
		checks["personal"] = h
	}
	selected := []policy.Probe{}
	for _, p := range probes {
		if skipCompany && p.Channel == "company" || selection.Current == selector.Reject && p.Channel == "personal" {
			continue
		}
		selected = append(selected, p)
	}
	observations := runProbeBatch(ctx, selected, 6*time.Second, 4, func(work context.Context, p policy.Probe) error { return probe(work, run, p, false) })
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	var personalFailure error
	for _, observation := range observations {
		p, failure := observation.probe, observation.err
		h := checks[p.Channel]
		h.Network = before.Manifest.Network
		h.Generation = before.VPN.Generation
		h.Node = selection.Current
		h.ChannelStatus = observeChannel(h.ChannelStatus, failure, observation.checked, p)
		h.ProbeScope = "system_tun"
		if failure != nil && p.Channel == "personal" && (personalFailure == nil || nodeProbeFailure(failure)) {
			personalFailure = failure
		}
		checks[p.Channel] = h
	}
	if personalFailure != nil {
		if err := rejectPersonal(run, selection, selection.Current, personalFailure); err != nil {
			return false, err
		}
		h := checks["personal"]
		h.Node = selector.Reject
		checks["personal"] = h
	}
	if !authorized || skipCompany {
		h := checks["company"]
		h.State, h.Reason, h.NextAction = "unavailable", "company_authorization_unavailable", "wait_for_reconnect"
		checks["company"] = h
	}
	ready := true
	for _, name := range []string{"company", "personal", "direct"} {
		ready = ready && checks[name].State == "ready"
	}
	err = update(run, func(s *State) error {
		if err := guard(run, s); err != nil {
			return err
		}
		if s.Manifest.Network != before.Manifest.Network || s.VPN.Generation != before.VPN.Generation {
			return errors.New("network generation changed during system checks")
		}
		s.Channels = checks
		return nil
	})
	return ready, err
}
