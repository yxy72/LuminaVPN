//go:build darwin || windows

package engine

import (
	"context"
	"errors"
	"time"

	"netlaunch/internal/policy"
	"netlaunch/internal/selector"
)

var errProbeScopeChanged = errors.New("probe scope changed")

// Only scoped system TUN observations are published as system health.
func checkSystemChannels(ctx context.Context, run string, schedule *probeSchedule, selection *selector.Policy, authorized, skipCompany bool) (bool, error) {
	before, err := load(run)
	if err != nil {
		return false, err
	}
	if err = guard(run, &before); err != nil {
		return false, err
	}
	node := selection.Current
	scope := scopeForProbes(before, node)
	selected := make([]policy.Probe, 0, len(before.Manifest.Config.Probes))
	for _, p := range before.Manifest.Config.Probes {
		if (!authorized || skipCompany) && p.Channel == "company" || node == selector.Reject && p.Channel == "personal" {
			continue
		}
		selected = append(selected, p)
	}
	schedule.bind(scope, selected)
	if !schedule.due(time.Now()) {
		return !systemReadyAt(before, time.Now()).IsZero(), ctx.Err()
	}
	if err = schedule.advance(ctx, func(work context.Context, p policy.Probe) error { return probe(work, run, p, node, nil) }); err != nil {
		return false, err
	}
	latest, err := load(run)
	if err != nil {
		return false, err
	}
	if err = guard(run, &latest); err != nil {
		return false, err
	}
	if scopeForProbes(latest, node) != scope || latest.Personal != before.Personal {
		schedule.reset()
		return false, nil
	}
	now := time.Now()
	checks := map[string]ChannelHealth{}
	var personalFailure error
	for _, channel := range []string{"company", "personal", "direct"} {
		status, failure := schedule.aggregate(channel, "system_tun", now)
		checks[channel] = ChannelHealth{
			ChannelStatus: status, Network: before.Manifest.Network, Generation: before.VPN.Generation, Node: node,
		}
		if channel == "personal" {
			personalFailure = failure
		}
	}
	if node == selector.Reject {
		// A deliberately closed ingress cannot verify the system path. Preserve
		// its actionable failure instead of replacing a service error with the
		// connection failure caused by our own REJECT gate.
		h := before.Channels["personal"]
		h.ChannelStatus = channelView(before, "personal", now)
		if h.State == "ready" {
			h.ChannelStatus = ChannelStatus{State: "unavailable", Reason: "no_verified_node", NextAction: "wait_for_selection"}
		}
		h.Node = selector.Reject
		checks["personal"] = h
	}
	recordedNode := before.Personal
	if personalFailure != nil {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if err := rejectPersonal(run, selection, node, personalFailure, "system_tun"); err != nil {
			return false, err
		}
		recordedNode = selector.Reject
		schedule.reset()
		h := checks["personal"]
		h.Node = selector.Reject
		checks["personal"] = h
	}
	if !authorized || skipCompany {
		h := checks["company"]
		h.ChannelStatus = ChannelStatus{
			State: "unavailable", Reason: "company_authorization_unavailable", NextAction: "wait_for_reconnect", CheckedAt: now,
		}
		if before.VPN.Bootstrap && !skipCompany {
			h.State, h.Reason, h.NextAction = "unknown", "probe_incomplete", "wait_for_probe"
		}
		checks["company"] = h
	}
	ready := false
	err = update(run, func(s *State) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := guard(run, s); err != nil {
			return err
		}
		if scopeForProbes(*s, node) != scope || s.Personal != recordedNode {
			return errProbeScopeChanged
		}
		s.Channels = checks
		checked := systemReadyAt(*s, time.Now())
		ready = !checked.IsZero()
		if !s.TakeoverActive {
			if ready {
				s.Phase, s.LastReady, s.Error = "ready", checked, ""
			} else if s.Phase == "ready" {
				s.Phase = "degraded"
			}
		}
		return nil
	})
	if errors.Is(err, errProbeScopeChanged) {
		schedule.reset()
		return false, nil
	}
	return ready, err
}

func systemReadyAt(s State, now time.Time) time.Time {
	var oldest time.Time
	for _, name := range []string{"company", "personal", "direct"} {
		h := channelView(s, name, now)
		if h.State != "ready" || h.ProbeScope != "system_tun" {
			return time.Time{}
		}
		if oldest.IsZero() || h.CheckedAt.Before(oldest) {
			oldest = h.CheckedAt
		}
	}
	return oldest
}
