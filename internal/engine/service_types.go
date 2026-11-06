package engine

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"netlaunch/internal/auth"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/runtimebundle"
)

type ServiceRunBinding struct {
	ServiceHost       platform.Identity `json:"service_host"`
	ServiceHostSHA256 string            `json:"service_host_sha256"`
	ProfileID         string            `json:"profile_id"`
	RunRef            string            `json:"run_ref"`
	ServiceInstance   string            `json:"service_instance"`
	CallerSID         string            `json:"caller_sid"`
	LogonSID          string            `json:"logon_sid"`
	AuthenticationID  string            `json:"authentication_id"`
	SessionID         uint32            `json:"session_id"`
	ExecutorSID       string            `json:"executor_sid"`
	Revision          uint64            `json:"revision"`
	Deadline          time.Time         `json:"deadline"`
	NodesSHA256       string            `json:"nodes_sha256"`
	RuntimeSHA256     string            `json:"runtime_sha256"`
	LifecycleSHA256   string            `json:"lifecycle_sha256"`
}
type ServicePrepareInput struct {
	Binding  ServiceRunBinding    `json:"binding"`
	Config   policy.Config        `json:"config"`
	Nodes    []policy.Node        `json:"nodes"`
	Mode     RunMode              `json:"mode"`
	Channels policy.ChannelIntent `json:"channels"`
	Auth     *auth.Session        `json:"auth,omitempty"`
}

// ServiceRuntime contains bytes read from the independently protected release
// catalog. It is never decoded from the helper's stdin or a user profile.
type ServiceRuntime struct {
	Manifest  runtimebundle.Manifest
	Files     map[string][]byte
	Lifecycle []byte
}
type ServicePrepared struct {
	RunID          string    `json:"run_id"`
	SpecDigest     string    `json:"spec_digest"`
	Mode           RunMode   `json:"mode"`
	Deadline       time.Time `json:"deadline"`
	CompanyPending bool      `json:"company_pending"`
}
type ServiceRunReference struct {
	ProfileID       string `json:"profile_id"`
	RunID           string `json:"run_id"`
	SpecDigest      string `json:"spec_digest"`
	BindingRunRef   string `json:"binding_run_ref"`
	ServiceInstance string `json:"service_instance"`
}

type ServicePreparationReference struct {
	ProfileID       string `json:"profile_id"`
	BindingRunRef   string `json:"binding_run_ref"`
	ServiceInstance string `json:"service_instance"`
}

func (r ServicePreparationReference) Validate() error {
	if !serviceProfileID.MatchString(r.ProfileID) || strings.Contains(r.ProfileID, "..") || !serviceOpaqueID.MatchString(r.BindingRunRef) || !serviceOpaqueID.MatchString(r.ServiceInstance) {
		return errors.New("invalid service preparation reference")
	}
	return nil
}

var serviceProfileID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
var serviceOpaqueID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var serviceSID = regexp.MustCompile(`^S-1-[0-9]+(?:-[0-9]+)+$`)
var serviceDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var serviceRunID = regexp.MustCompile(`^netlaunch-[a-f0-9]{32}$`)

func (b ServiceRunBinding) Validate(mode RunMode, created time.Time) error {
	if platform.WindowsClientValidationOnly && mode != Validation {
		return errors.New("this reviewed service build permits validation mode only")
	}
	if b.ServiceHost.PID < 2 || b.ServiceHost.Birth == "" || b.ServiceHost.OwnerSID != "S-1-5-18" || b.ServiceHost.Executable == "" || !serviceDigest.MatchString(b.ServiceHostSHA256) {
		return errors.New("fixed live service owner identity missing")
	}
	if !serviceProfileID.MatchString(b.ProfileID) || strings.Contains(b.ProfileID, "..") || !serviceOpaqueID.MatchString(b.RunRef) || !serviceOpaqueID.MatchString(b.ServiceInstance) || !serviceSID.MatchString(b.CallerSID) || !serviceSID.MatchString(b.LogonSID) || b.CallerSID == "S-1-5-18" || b.SessionID == 0 || b.AuthenticationID == "" || len(b.AuthenticationID) > 128 || b.ExecutorSID != "S-1-5-18" || b.Revision == 0 {
		return errors.New("invalid service-owned run binding")
	}
	if mode == Daily {
		if !b.Deadline.IsZero() {
			return errors.New("daily service run cannot have deadline")
		}
	} else if mode == Validation {
		if created.IsZero() || !b.Deadline.After(created) || b.Deadline.Sub(created) > 45*time.Minute {
			return errors.New("service validation deadline exceeds immutable 45 minute bound")
		}
	} else {
		return errors.New("explicit service run mode required")
	}
	return nil
}
func (r ServiceRunReference) Validate() error {
	if !serviceProfileID.MatchString(r.ProfileID) || !serviceRunID.MatchString(r.RunID) || !serviceDigest.MatchString(r.SpecDigest) || !serviceOpaqueID.MatchString(r.BindingRunRef) || !serviceOpaqueID.MatchString(r.ServiceInstance) {
		return errors.New("invalid service run reference")
	}
	return nil
}
