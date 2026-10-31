package app

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netlaunch/internal/engine"
)

// Diagnostic exports deliberately do not embed Status: its node names and free
// text errors may be private, and future fields must not silently become public.
type diagnosticReport struct {
	Version         int               `json:"version"`
	ExporterBuild   buildIdentity     `json:"exporter_build"`
	Scope           string            `json:"scope"`
	RuntimeLiveness string            `json:"runtime_liveness"`
	StatusRead      string            `json:"status_read"`
	Status          *diagnosticStatus `json:"status,omitempty"`
}

type diagnosticStatus struct {
	Phase              string                       `json:"phase"`
	Lifecycle          string                       `json:"lifecycle"`
	HasError           bool                         `json:"has_error"`
	RecoveryReason     string                       `json:"recovery_reason"`
	SnapshotAgeSeconds *int64                       `json:"snapshot_age_seconds,omitempty"`
	Channels           map[string]diagnosticChannel `json:"channels"`
}

type diagnosticChannel struct {
	State        string `json:"state"`
	Reason       string `json:"reason"`
	NextAction   string `json:"next_action"`
	PathState    string `json:"path_state"`
	ServiceState string `json:"service_state"`
	ProbeScope   string `json:"probe_scope"`
}

// Exact membership is intentional: accepting arbitrary snake_case values would
// still disclose node labels, hostnames or tokens stored in malformed records.
func publicCode(value, allowed string) string {
	for _, candidate := range strings.Fields(allowed) {
		if value == candidate {
			return value
		}
	}
	return "unknown"
}

const diagnosticReasons = `path_verified service_healthy path_probe_failed http_response_missing
http_status_rejected tcp_unavailable tls_certificate_invalid tls_timeout tls_failed http_write_failed
probe_budget_expired check_expired stopped stopping recovery_failed physical_network_unavailable
authentication_required vpn_not_ready company_check_failed generation_changed lease_unavailable
no_verified_node selection_changed not_checked network_changed core_ingress_unavailable
core_configuration_unavailable core_binding_invalid core_request_invalid core_request_interrupted
core_unavailable core_request_rejected core_response_invalid
coordinator_unresponsive coordinator_stalled coordinator_monitor_invalid coordinator_exit coordinator_exited
user_stop stop_marker_unreadable explicit_recovery cancelled_before_network_changes
validation_deadline validation_deadline_changed startup_or_runtime_failed wake_identity_unavailable lease_guard_expired
vpn_child_gate_expired vpn_runtime_load_failed vpn_hook_failed vpn_permission_denied vpn_stdin_failed
vpn_tun_failed vpn_certificate_rejected vpn_exit_observation_failed vpn_failure_classification_invalid`

func diagnosticProjection(s engine.Status, now time.Time) *diagnosticStatus {
	s = engine.RefreshStatus(s, now)
	d := &diagnosticStatus{
		Phase:          publicCode(s.Phase, "prepared preparing starting reconnecting ready degraded network_unavailable company_unavailable authentication_required stopping stopped recovery_failed"),
		Lifecycle:      publicCode(s.Lifecycle, "starting running stopping stopped recovery_failed"),
		HasError:       s.Error != "",
		RecoveryReason: publicCode(s.RecoveryReason, diagnosticReasons),
		Channels:       map[string]diagnosticChannel{},
	}
	if s.RecoveryReason == "" {
		d.RecoveryReason = "none"
	}
	if !s.Updated.IsZero() && !now.Before(s.Updated) {
		age := int64(now.Sub(s.Updated) / time.Second)
		d.SnapshotAgeSeconds = &age
	}
	for _, name := range []string{"company", "personal", "direct"} {
		h := s.Channels[name]
		d.Channels[name] = diagnosticChannel{
			State:        publicCode(h.State, "ready unavailable unknown"),
			Reason:       publicCode(h.Reason, diagnosticReasons),
			NextAction:   publicCode(h.NextAction, "check_company check_personal check_direct check_runtime check_service_expectation wait_for_probe start run_down check_network run_auth wait_for_reconnect wait_for_renewal wait_for_selection check_status"),
			PathState:    publicCode(h.PathState, "verified failed unknown not_checked"),
			ServiceState: publicCode(h.ServiceState, "healthy failed unknown not_checked"),
			ProbeScope:   publicCode(h.ProbeScope, "system_tun mixed_ingress"),
		}
	}
	return d
}

func (c CLI) diagnostics(args []string) error {
	if len(args) == 0 || args[0] != "export" {
		return errors.New("use diagnostics export [--profile DIR] [--run DIR]; JSON is written to stdout")
	}
	profile, err := DefaultProfile()
	if err != nil {
		return errors.New("default profile unavailable; diagnostics not collected")
	}
	o := options{}
	fs := flag.NewFlagSet("diagnostics export", flag.ContinueOnError)
	fs.SetOutput(c.Err)
	fs.StringVar(&o.profile, "profile", profile, "private local profile directory")
	fs.StringVar(&o.run, "run", "", "specific run directory")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected diagnostics arguments")
	}
	o.profile, err = filepath.Abs(o.profile)
	if err != nil {
		return errors.New("diagnostic profile path unavailable")
	}
	if o.run != "" {
		o.run, err = filepath.Abs(o.run)
		if err != nil {
			return errors.New("diagnostic run path unavailable")
		}
	}
	r := diagnosticReport{Version: 1, ExporterBuild: currentBuildIdentity(), Scope: "saved_status", RuntimeLiveness: "not_checked", StatusRead: "run_reference_unavailable"}
	if o.run == "" {
		if _, err := os.Lstat(filepath.Join(o.profile, "current.json")); errors.Is(err, os.ErrNotExist) {
			r.StatusRead = "no_current_run"
			return c.json(r)
		}
	}
	if run, err := currentRun(o); err == nil {
		r.StatusRead = "status_unavailable"
		if s, err := statusFor(run); err == nil {
			r.StatusRead, r.Status = "available", diagnosticProjection(s, time.Now())
		}
	}
	return c.json(r)
}
