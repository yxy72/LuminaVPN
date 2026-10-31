package engine

import (
	"context"
	"errors"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
)

// ChannelStatus separates path evidence from configured HTTP expectations.
// It never claims business login or includes private endpoint names.
type ChannelStatus struct {
	State        string    `json:"state"`
	Reason       string    `json:"reason,omitempty"`
	CheckedAt    time.Time `json:"checked_at"`
	NextAction   string    `json:"next_action,omitempty"`
	PathState    string    `json:"path_state,omitempty"`
	ServiceState string    `json:"service_state,omitempty"`
	ProbeScope   string    `json:"probe_scope,omitempty"`
}

type ChannelHealth struct {
	ChannelStatus
	Network    platform.Network `json:"network"`
	Generation string           `json:"generation,omitempty"`
	Node       string           `json:"node,omitempty"`
}

func observeChannel(previous ChannelStatus, failure error, checked time.Time, p policy.Probe) ChannelStatus {
	next := ChannelStatus{State: "ready", Reason: "path_verified", CheckedAt: checked, PathState: "verified", ServiceState: "not_checked"}
	if p.EffectivePurpose() == "service" {
		next.Reason, next.ServiceState = "service_healthy", "healthy"
	}
	if failure != nil {
		next.State, next.Reason, next.NextAction = "unavailable", probeReason(failure), "check_"+p.Channel
		next.PathState, next.ServiceState = "failed", "unknown"
		var core *coreFailure
		switch {
		case errors.As(failure, &core):
			next.State, next.PathState, next.NextAction = "unknown", "unknown", "check_runtime"
		case errors.Is(failure, context.Canceled), errors.Is(failure, context.DeadlineExceeded):
			next.State, next.PathState, next.Reason, next.NextAction = "unknown", "unknown", "probe_budget_expired", "wait_for_probe"
		case probeReason(failure) == "http_status_rejected":
			next.PathState, next.ServiceState = "verified", "failed"
			next.NextAction = "check_service_expectation"
		}
	}
	if previous.State == "" {
		return next
	}
	path := mergeEvidence(previous.PathState, next.PathState, "verified")
	service := mergeEvidence(previous.ServiceState, next.ServiceState, "healthy")
	if previous.State == "unavailable" || previous.State == "unknown" && next.State == "ready" {
		next = previous
	}
	if next.State == "ready" && service == "healthy" {
		next.Reason = "service_healthy"
	}
	next.PathState, next.ServiceState = path, service
	return next
}

func mergeEvidence(a, b, success string) string {
	for _, value := range []string{"failed", "unknown", success, "not_checked"} {
		if a == value || b == value {
			return value
		}
	}
	return ""
}

func ageProbeEvidence(h ChannelStatus, now time.Time) ChannelStatus {
	if h.CheckedAt.IsZero() || now.Before(h.CheckedAt) || now.Sub(h.CheckedAt) > 90*time.Second {
		if h.PathState != "" {
			h.PathState = "unknown"
		}
		if h.ServiceState != "" {
			h.ServiceState = "unknown"
		}
		if h.State == "ready" {
			h.State, h.Reason, h.NextAction = "unknown", "check_expired", "wait_for_probe"
		}
	}
	return h
}

func invalidateChannelHealth(before State, after *State) {
	if before.Manifest.Network != after.Manifest.Network || after.Phase == "network_unavailable" || after.Phase == "stopping" || after.Phase == "stopped" || after.Phase == "recovery_failed" {
		after.Channels = nil
		return
	}
	if before.VPN.Generation != after.VPN.Generation || !after.VPN.Bootstrap {
		delete(after.Channels, "company")
	}
	if before.Personal != after.Personal && after.Channels["personal"].Node != after.Personal {
		delete(after.Channels, "personal")
	}
}

func channelView(s State, name string, now time.Time) ChannelStatus {
	h, ok := s.Channels[name]
	out := ageProbeEvidence(h.ChannelStatus, now)
	unknown := func(reason string) ChannelStatus {
		return ChannelStatus{State: "unknown", Reason: reason, CheckedAt: out.CheckedAt, NextAction: "wait_for_probe"}
	}
	if name == "company" && s.Phase == "stopped" && s.RecoveryReason == "authentication_required" {
		return ChannelStatus{State: "unavailable", Reason: "authentication_required", NextAction: "run_auth"}
	}
	switch s.Phase {
	case "stopped", "stopping":
		return ChannelStatus{State: "unavailable", Reason: s.Phase, NextAction: "start"}
	case "recovery_failed":
		return ChannelStatus{State: "unavailable", Reason: "recovery_failed", NextAction: "run_down"}
	case "network_unavailable":
		return ChannelStatus{State: "unavailable", Reason: "physical_network_unavailable", NextAction: "check_network"}
	}
	if name == "company" {
		if s.Phase == "authentication_required" {
			return ChannelStatus{State: "unavailable", Reason: "authentication_required", NextAction: "run_auth"}
		}
		if !s.VPN.Bootstrap {
			return ChannelStatus{State: "unavailable", Reason: "vpn_not_ready", NextAction: "wait_for_reconnect"}
		}
		if s.Phase == "company_unavailable" {
			return ChannelStatus{State: "unavailable", Reason: "company_check_failed", NextAction: "check_company"}
		}
		if h.Generation != s.VPN.Generation {
			return unknown("generation_changed")
		}
		for _, domain := range s.Manifest.Config.Company.Domains {
			valid := false
			for _, a := range s.Leases {
				if a.Domain == domain && now.Before(a.ExpiresAt) {
					valid = true
					break
				}
			}
			if !valid {
				return ChannelStatus{State: "unavailable", Reason: "lease_unavailable", NextAction: "wait_for_renewal"}
			}
		}
	}
	if name == "personal" {
		if s.Personal == "" || s.Personal == "REJECT" {
			if ok && (out.State == "unavailable" || out.State == "unknown") {
				return out
			}
			return ChannelStatus{State: "unavailable", Reason: "no_verified_node", NextAction: "wait_for_selection"}
		}
		if h.Node != s.Personal {
			return unknown("selection_changed")
		}
	}
	if !ok {
		return unknown("not_checked")
	}
	if h.Network != s.Manifest.Network {
		return unknown("network_changed")
	}
	if out.CheckedAt.IsZero() || now.Before(out.CheckedAt) || now.Sub(out.CheckedAt) > 90*time.Second {
		return unknown("check_expired")
	}
	return out
}

func NeedsAuthentication(s Status) bool {
	return s.Phase == "authentication_required" || (s.Phase == "stopped" && s.RecoveryReason == "authentication_required")
}

func publicStatus(s State, now time.Time) Status {
	channels := map[string]ChannelStatus{}
	allReady := true
	for _, name := range []string{"company", "personal", "direct"} {
		channels[name] = channelView(s, name, now)
		allReady = allReady && channels[name].State == "ready"
	}
	phase := s.Phase
	if phase == "ready" && !allReady {
		phase = "degraded"
	}
	lifecycle := "starting"
	switch s.Phase {
	case "stopped", "stopping", "recovery_failed":
		lifecycle = s.Phase
	default:
		if !s.LastReady.IsZero() || s.Phase == "ready" {
			lifecycle = "running"
		}
	}
	return Status{Phase: phase, Updated: s.Updated, Company: channels["company"].State, Personal: s.Personal, LastReady: s.LastReady, Error: s.Error, RecoveryReason: s.RecoveryReason, Experimental: true, Channels: channels, Lifecycle: lifecycle}
}

func personalUnavailable(s *State, reason string) {
	if s.Channels == nil {
		s.Channels = map[string]ChannelHealth{}
	}
	s.Channels["personal"] = ChannelHealth{ChannelStatus: ChannelStatus{State: "unavailable", Reason: reason, CheckedAt: time.Now(), NextAction: "wait_for_selection"}, Network: s.Manifest.Network, Node: s.Personal}
}

// RefreshStatus ages public evidence even when the coordinator has stopped
// updating its status file. It does not infer availability for legacy records.
func RefreshStatus(s Status, now time.Time) Status {
	if s.Channels == nil {
		return s
	}
	channels := make(map[string]ChannelStatus, len(s.Channels))
	for name, h := range s.Channels {
		wasReady := h.State == "ready"
		h = ageProbeEvidence(h, now)
		if wasReady && h.State != "ready" {
			h.State, h.Reason, h.NextAction = "unknown", "check_expired", "check_status"
			if s.Phase == "ready" {
				s.Phase = "degraded"
			}
		}
		channels[name] = h
	}
	s.Channels = channels
	s.Company = channels["company"].State
	return s
}
