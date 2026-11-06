// Package serviceprotocol is the bounded, data-only Windows service contract.
// It intentionally contains no executable paths, argv, shell or user run paths.
package serviceprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"netlaunch/internal/policy"
)

const Version = 1
const MaxFrame = 1 << 20

type Kind string

const (
	TakeoverStart    Kind = "takeover_start"
	ChannelsSet      Kind = "channels_set"
	TakeoverStop     Kind = "takeover_stop"
	ExitRestore      Kind = "exit_restore"
	ProfileApply     Kind = "profile_apply"
	AuthRespond      Kind = "auth_respond"
	AuthCancel       Kind = "auth_cancel"
	NodeSelect       Kind = "node_select"
	SettingsApply    Kind = "settings_apply"
	Workspace        Kind = "workspace"
	AttachEnrollment Kind = "attach_enrollment"
)

type DesiredChannels struct {
	Company  bool `json:"company"`
	Personal bool `json:"personal"`
}

type StartPayload struct {
	Channels          DesiredChannels `json:"channels"`
	Mode              string          `json:"mode"`
	ValidationSeconds int             `json:"validation_seconds,omitempty"`
}
type StopPayload struct{}
type AttachPayload struct{}
type ProfilePayload struct {
	Policy policy.Config `json:"policy"`
	Nodes  []policy.Node `json:"nodes"`
	Name   string        `json:"name"`
}
type AuthPayload struct {
	ChallengeID string           `json:"challenge_id"`
	Sequence    uint64           `json:"sequence"`
	Username    string           `json:"username,omitempty"`
	Password    string           `json:"password,omitempty"`
	OTP         string           `json:"otp,omitempty"`
	Fields      []AuthFieldValue `json:"fields,omitempty"`
}
type AuthFieldValue struct {
	FieldID string `json:"field_id"`
	Value   string `json:"value"`
}
type AuthChoice struct {
	ChoiceID string `json:"choice_id"`
	Label    string `json:"label"`
}
type AuthField struct {
	FieldID   string       `json:"field_id"`
	Kind      string       `json:"kind"`
	LabelCode string       `json:"label_code,omitempty"`
	Choices   []AuthChoice `json:"choices,omitempty"`
}

func (a AuthPayload) Validate() error {
	if !ValidID(a.ChallengeID) || a.Sequence == 0 || len(a.Username) > 256 || len(a.Password) > 4096 || len(a.OTP) > 1024 || strings.ContainsAny(a.Username+a.Password+a.OTP, "\x00\r\n") || len(a.Fields) > 16 {
		return errors.New("invalid bounded challenge response")
	}
	if len(a.Fields) > 0 && a.Username+a.Password+a.OTP != "" {
		return errors.New("mixed legacy and field challenge response")
	}
	seen := map[string]bool{}
	for _, field := range a.Fields {
		if !ValidID(field.FieldID) || seen[field.FieldID] || len(field.Value) > 4096 || strings.ContainsAny(field.Value, "\x00\r\n") {
			return errors.New("invalid challenge field response")
		}
		seen[field.FieldID] = true
	}
	return nil
}

type CancelAuthPayload struct {
	ChallengeID string `json:"challenge_id"`
}
type SelectionPayload struct {
	NodeID string `json:"node_id"` // "auto" or a service-issued opaque node id.
}
type SettingsPayload struct {
	AutoConnect     bool       `json:"auto_connect"`
	Environment     string     `json:"environment"`
	OfficeOverrides []Override `json:"office_overrides"`
	HomeOverrides   []Override `json:"home_overrides"`
}
type Override struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Target string `json:"target"`
}

func (s SettingsPayload) MarshalJSON() ([]byte, error) {
	type plain SettingsPayload
	copy := plain(s)
	if copy.OfficeOverrides == nil {
		copy.OfficeOverrides = []Override{}
	}
	if copy.HomeOverrides == nil {
		copy.HomeOverrides = []Override{}
	}
	return json.Marshal(copy)
}

type WorkspacePayload struct {
	Action                 string          `json:"action"`
	PolicyJSON             json.RawMessage `json:"policy_json,omitempty"`
	BootstrapJSON          json.RawMessage `json:"bootstrap_json,omitempty"`
	ExpectedPolicyRevision string          `json:"expected_policy_revision,omitempty"`
	Revision               string          `json:"revision,omitempty"`
	Content                string          `json:"content,omitempty"`
	OpaqueRunID            string          `json:"opaque_run_id,omitempty"`
	SourcesJSON            json.RawMessage `json:"sources_json,omitempty"`
}

func (w WorkspacePayload) Validate() error {
	allowed := false
	switch w.Action {
	case "initialize":
		allowed = (len(w.PolicyJSON) > 0) != (len(w.BootstrapJSON) > 0) && w.ExpectedPolicyRevision == "" && w.Revision == "" && w.Content == "" && w.OpaqueRunID == "" && len(w.SourcesJSON) == 0
	case "apply":
		allowed = len(w.PolicyJSON) > 0 && len(w.BootstrapJSON) == 0 && w.Revision == "" && w.Content == "" && w.OpaqueRunID == "" && len(w.SourcesJSON) == 0
	case "rollback":
		allowed = w.Revision != "" && len(w.PolicyJSON)+len(w.BootstrapJSON) == 0 && w.Content == "" && w.OpaqueRunID == "" && len(w.SourcesJSON) == 0
	case "import_nodes":
		allowed = w.Content != "" && len(w.PolicyJSON)+len(w.BootstrapJSON) == 0 && w.Revision == "" && w.OpaqueRunID == "" && len(w.SourcesJSON) == 0
	case "sync":
		allowed = len(w.PolicyJSON)+len(w.BootstrapJSON) == 0 && w.Revision == "" && w.Content == "" && w.OpaqueRunID == "" && len(w.SourcesJSON) == 0
	case "sources_save":
		allowed = len(w.SourcesJSON) > 0 && w.Content == "" && len(w.PolicyJSON)+len(w.BootstrapJSON) == 0 && w.Revision == "" && w.OpaqueRunID == ""
	case "cleanup":
		allowed = ValidID(w.OpaqueRunID) && len(w.PolicyJSON)+len(w.BootstrapJSON) == 0 && w.Revision == "" && w.Content == "" && len(w.SourcesJSON) == 0
	}
	if !allowed || len(w.PolicyJSON) > 64<<10 || len(w.BootstrapJSON) > 64<<10 || len(w.SourcesJSON) > 64<<10 || len(w.Content) > 700<<10 || len(w.ExpectedPolicyRevision) > 128 || len(w.Revision) > 128 {
		return errors.New("invalid typed workspace action or fields")
	}
	if len(w.PolicyJSON) > 0 && !json.Valid(w.PolicyJSON) || len(w.BootstrapJSON) > 0 && !json.Valid(w.BootstrapJSON) || len(w.SourcesJSON) > 0 && !json.Valid(w.SourcesJSON) {
		return errors.New("invalid workspace JSON document")
	}
	return nil
}

// Mutation has exactly one typed payload selected by Kind. Credentials are
// transient input, never copied into operation snapshots or a recovery journal.
type Mutation struct {
	RequestID        string             `json:"request_id"`
	ProfileID        string             `json:"profile_id"`
	ExpectedRevision uint64             `json:"expected_revision"`
	RunRef           string             `json:"run_ref,omitempty"`
	Kind             Kind               `json:"kind"`
	Start            *StartPayload      `json:"start,omitempty"`
	Channels         *DesiredChannels   `json:"channels,omitempty"`
	Stop             *StopPayload       `json:"stop,omitempty"`
	Profile          *ProfilePayload    `json:"profile,omitempty"`
	Auth             *AuthPayload       `json:"auth,omitempty"`
	CancelAuth       *CancelAuthPayload `json:"cancel_auth,omitempty"`
	Selection        *SelectionPayload  `json:"selection,omitempty"`
	Settings         *SettingsPayload   `json:"settings,omitempty"`
	Workspace        *WorkspacePayload  `json:"workspace,omitempty"`
	Attach           *AttachPayload     `json:"attach,omitempty"`
}

var opaqueID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

func ValidID(id string) bool { return opaqueID.MatchString(id) }
func (m Mutation) PriorityStop() bool {
	return m.Kind == TakeoverStop || m.Kind == ExitRestore || m.Kind == AttachEnrollment
}

func (m Mutation) Validate() error {
	if !ValidID(m.RequestID) || !ValidID(m.ProfileID) || m.RunRef != "" && !ValidID(m.RunRef) {
		return errors.New("invalid opaque request/profile/run identifier")
	}
	count := 0
	for _, exists := range []bool{m.Start != nil, m.Channels != nil, m.Stop != nil, m.Profile != nil,
		m.Auth != nil, m.CancelAuth != nil, m.Selection != nil, m.Settings != nil, m.Workspace != nil, m.Attach != nil} {
		if exists {
			count++
		}
	}
	if count != 1 {
		return errors.New("exactly one typed mutation payload is required")
	}
	valid := false
	switch m.Kind {
	case TakeoverStart:
		valid = m.Start != nil
		if valid {
			switch m.Start.Mode {
			case "daily":
				valid = m.Start.ValidationSeconds == 0
			case "validation":
				valid = m.Start.ValidationSeconds >= 1 && m.Start.ValidationSeconds <= 2700
			case "legacy_home":
				valid = false
			default:
				valid = false
			}
		}
	case ChannelsSet:
		valid = m.Channels != nil
	case TakeoverStop, ExitRestore:
		valid = m.Stop != nil
	case AttachEnrollment:
		valid = m.Attach != nil && m.ExpectedRevision == 0 && m.RunRef == ""
	case ProfileApply:
		valid = m.Profile != nil && len(m.Profile.Name) <= 128
		if valid {
			if err := m.Profile.Policy.ValidateForStorage(); err != nil {
				return errors.New("profile policy validation failed")
			}
			if _, err := policy.SanitizeNodes(m.Profile.Nodes); len(m.Profile.Nodes) > 0 && err != nil {
				return errors.New("profile node validation failed")
			}
		}
	case AuthRespond:
		valid = m.Auth != nil && m.Auth.Validate() == nil
	case AuthCancel:
		valid = m.CancelAuth != nil && ValidID(m.CancelAuth.ChallengeID)
	case NodeSelect:
		valid = m.Selection != nil && ValidID(m.Selection.NodeID)
	case SettingsApply:
		valid = m.Settings != nil && (m.Settings.Environment == "office" || m.Settings.Environment == "home")
		if valid {
			for _, group := range [][]Override{m.Settings.OfficeOverrides, m.Settings.HomeOverrides} {
				if len(group) > 128 {
					return errors.New("override limit exceeded")
				}
				for _, rule := range group {
					if rule.Target != "personal" && rule.Target != "direct" {
						return errors.New("invalid environment override target")
					}
					if rule.Type != "domain" && rule.Type != "domain_suffix" && rule.Type != "cidr" {
						return errors.New("invalid environment override type")
					}
					if len(rule.Value) == 0 || len(rule.Value) > 253 {
						return errors.New("invalid override value")
					}
					if rule.Type == "cidr" {
						prefix, err := netip.ParsePrefix(rule.Value)
						if err != nil || prefix != prefix.Masked() {
							return errors.New("invalid override prefix")
						}
					} else if !policy.ValidDomain(rule.Value) {
						return errors.New("invalid exact override domain")
					}
				}
			}
		}
	case Workspace:
		valid = m.Workspace != nil
		if valid {
			return m.Workspace.Validate()
		}
	}
	if !valid {
		return errors.New("unsupported mutation or mismatched typed payload")
	}
	return nil
}

type Error struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

type Operation struct {
	AliasOf      string    `json:"alias_of,omitempty"`
	ID           string    `json:"operation_id"`
	RequestID    string    `json:"request_id"`
	ProfileID    string    `json:"profile_id"`
	RunRef       string    `json:"run_ref,omitempty"`
	Revision     uint64    `json:"revision"`
	Kind         Kind      `json:"kind"`
	Phase        string    `json:"phase"`
	Completed    bool      `json:"completed"`
	Restored     bool      `json:"restored"`
	Created      time.Time `json:"created_at"`
	Updated      time.Time `json:"updated_at"`
	Error        *Error    `json:"error,omitempty"`
	FirstFailure *Error    `json:"first_failure,omitempty"`
}
type Channel struct {
	Desired     bool         `json:"desired"`
	State       string       `json:"state"`
	Route       string       `json:"route"`
	Reason      string       `json:"reason,omitempty"`
	HealthEpoch string       `json:"health_epoch,omitempty"`
	IPv6        string       `json:"ipv6_state,omitempty"`
	Health      *HealthRound `json:"health,omitempty"`
}
type CandidateHealth struct {
	ID              string `json:"id"`
	State           string `json:"state"`
	FailureScope    string `json:"failure_scope"`
	Epoch           string `json:"epoch"`
	ConfigRevision  string `json:"config_revision"`
	NodeSetRevision string `json:"node_set_revision"`
}
type HealthRound struct {
	Epoch                string            `json:"epoch"`
	ConfigRevision       string            `json:"config_revision"`
	NodeSetRevision      string            `json:"node_set_revision"`
	ExpectedCandidateIDs []string          `json:"expected_candidate_ids"`
	Candidates           []CandidateHealth `json:"candidates"`
}
type Challenge struct {
	ID       string      `json:"challenge_id"`
	Kind     string      `json:"kind"`
	Expires  time.Time   `json:"expires_at"`
	Sequence uint64      `json:"sequence"`
	Fields   []AuthField `json:"fields,omitempty"`
}

// LocalExitProof is synthesized only by the local Windows client from fixed
// SCM/filesystem evidence. A service RPC response is not authority for it.
type LocalExitProof struct {
	Source        string `json:"source"`
	ServiceAbsent bool   `json:"service_absent"`
	NoOwnedState  bool   `json:"no_owned_state"`
}
type Snapshot struct {
	ProtocolVersion  int              `json:"protocol_version"`
	ServiceState     string           `json:"service_state"`
	TakeoverState    string           `json:"takeover_state"`
	ProfileID        string           `json:"profile_id"`
	Revision         uint64           `json:"revision"`
	RunRef           string           `json:"run_ref,omitempty"`
	Desired          DesiredChannels  `json:"desired"`
	Company          Channel          `json:"company"`
	Personal         Channel          `json:"personal"`
	OperationID      string           `json:"operation_id,omitempty"`
	Challenge        *Challenge       `json:"challenge,omitempty"`
	RecoveryRequired bool             `json:"recovery_required"`
	Restored         bool             `json:"restored"`
	AutoConnect      bool             `json:"auto_connect"`
	Settings         *SettingsPayload `json:"settings,omitempty"`
	LocalExitProof   *LocalExitProof  `json:"local_exit_proof,omitempty"`
}

type Client interface {
	Snapshot(context.Context, string) (Snapshot, error)
	Submit(context.Context, Mutation) (Operation, error)
	Operation(context.Context, string) (Operation, error)
}

type Request struct {
	Version     int       `json:"version"`
	Method      string    `json:"method"` // snapshot, submit or operation only.
	ProfileID   string    `json:"profile_id,omitempty"`
	OperationID string    `json:"operation_id,omitempty"`
	Mutation    *Mutation `json:"mutation,omitempty"`
}
type Response struct {
	Snapshot  *Snapshot  `json:"snapshot,omitempty"`
	Operation *Operation `json:"operation,omitempty"`
	Error     *Error     `json:"error,omitempty"`
}

func DecodeRequest(data []byte) (Request, error) {
	var r Request
	if len(data) == 0 || len(data) > MaxFrame {
		return r, errors.New("invalid frame size")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, errors.New("invalid typed service request")
	}
	if d.Decode(new(any)) != io.EOF {
		return r, errors.New("trailing service request data")
	}
	if r.Version != Version {
		return r, errors.New("unsupported service protocol version")
	}
	switch r.Method {
	case "snapshot":
		if !ValidID(r.ProfileID) || r.Mutation != nil || r.OperationID != "" {
			return r, errors.New("invalid snapshot request")
		}
	case "operation":
		if !ValidID(r.OperationID) || r.Mutation != nil || r.ProfileID != "" {
			return r, errors.New("invalid operation request")
		}
	case "submit":
		if r.Mutation == nil || r.ProfileID != "" || r.OperationID != "" {
			return r, errors.New("invalid mutation request")
		}
		if err := r.Mutation.Validate(); err != nil {
			return r, err
		}
	default:
		return r, errors.New("unsupported service method")
	}
	return r, nil
}
