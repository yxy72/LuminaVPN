package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"strings"

	"netlaunch/internal/app"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/serviceprotocol"
)

var ClientMethods = []string{"service.snapshot", "service.submit", "service.operation", "workspace.read", "workspace.submit"}

func (d *Desktop) desktopPolicy() (policy.Config, error) {
	if d.ClientEnabled() {
		return app.DesktopWorkspacePolicy(d.Profile)
	}
	return app.DesktopPolicy(d.Profile)
}
func (d *Desktop) desktopNodes(cfg policy.Config) ([]policy.Node, error) {
	if d.ClientEnabled() {
		return app.DesktopWorkspaceNodes(d.Profile, cfg)
	}
	return app.DesktopNodes(d.Profile, cfg)
}
func (d *Desktop) desktopRules(cfg policy.Config) ([]policy.PlannedRule, error) {
	if d.ClientEnabled() {
		return app.DesktopWorkspaceRules(d.Profile, cfg)
	}
	return app.DesktopRules(d.Profile, cfg)
}
func (d *Desktop) desktopSubscriptions(cfg policy.Config) (app.DesktopSubscription, error) {
	if d.ClientEnabled() {
		return app.DesktopWorkspaceSubscriptions(d.Profile, cfg)
	}
	return app.DesktopSubscriptions(d.Profile, cfg)
}

func IsClientMethod(method string) bool {
	for _, m := range ClientMethods {
		if m == method {
			return true
		}
	}
	return false
}
func (d *Desktop) ClientEnabled() bool { return runtime.GOOS == "windows" && d.Control != nil }
func (d *Desktop) ClientProfileID() string {
	sum := sha256.Sum256([]byte(strings.ToLower(d.Profile)))
	return hex.EncodeToString(sum[:16])
}
func clientDecode(raw json.RawMessage, target any) error {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if len(raw) > 1<<20 {
		return errors.New("request too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid client payload")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing client payload")
	}
	return nil
}
func clientFailure(err error) error {
	if err == nil {
		return nil
	}
	var safe *serviceprotocol.Error
	if errors.As(err, &safe) {
		return &Error{Code: safe.Code, Message: "The requested service operation could not be completed.", Retryable: safe.Retryable}
	}
	return unavailable("CLIENT_OPERATION_FAILED", "The requested local operation failed; private details omitted.")
}

type workspaceRead struct {
	ProfileID  string `json:"profile_id"`
	Action     string `json:"action"`
	PolicyJSON string `json:"policy_json,omitempty"`
	Target     string `json:"target,omitempty"`
}
type workspaceWrite struct {
	ProfileID        string `json:"profile_id"`
	RequestID        string `json:"request_id"`
	Action           string `json:"action"`
	PolicyJSON       string `json:"policy_json,omitempty"`
	BootstrapJSON    string `json:"bootstrap_json,omitempty"`
	ExpectedRevision string `json:"expected_revision,omitempty"`
	Revision         string `json:"revision,omitempty"`
	Content          string `json:"content,omitempty"`
	OpaqueRunID      string `json:"opaque_run_id,omitempty"`
	SourcesJSON      string `json:"sources_json,omitempty"`
}

func onlyClientKeys(raw json.RawMessage, allowed ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return false
	}
	for key := range fields {
		found := false
		for _, v := range allowed {
			if key == v {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func (d *Desktop) ClientRequest(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	if !d.ClientEnabled() {
		return nil, unavailable("CLIENT_UNAVAILABLE", "Windows client controls are unavailable in this build.")
	}
	switch method {
	case "service.snapshot":
		if !onlyClientKeys(raw) {
			return nil, unavailable("INVALID_PARAMS", "No parameters are accepted.")
		}
		snapshot, err := d.Control.Snapshot(ctx, d.ClientProfileID())
		if err != nil {
			return nil, clientFailure(err)
		}
		if snapshot.ProfileID != d.ClientProfileID() {
			return nil, unavailable("PROFILE_MISMATCH", "The service profile did not match the selected workspace.")
		}
		return snapshot, nil
	case "service.operation":
		var p struct {
			ID string `json:"operation_id"`
		}
		if clientDecode(raw, &p) != nil || !serviceprotocol.ValidID(p.ID) {
			return nil, unavailable("INVALID_PARAMS", "One operation identifier is required.")
		}
		op, err := d.Control.Operation(ctx, p.ID)
		if err != nil {
			return nil, clientFailure(err)
		}
		if op.ProfileID != d.ClientProfileID() || op.ID != p.ID {
			return nil, unavailable("OPERATION_MISMATCH", "Operation belongs to a different profile.")
		}
		return op, nil
	case "service.submit":
		var mutation serviceprotocol.Mutation
		if clientDecode(raw, &mutation) != nil || mutation.Validate() != nil || mutation.ProfileID != d.ClientProfileID() || mutation.Kind == serviceprotocol.Workspace || !validDesktopStart(mutation.Start) {
			return nil, unavailable("INVALID_PARAMS", "The typed service mutation is invalid.")
		}
		operation, err := d.Control.Submit(ctx, mutation)
		if err == nil && (operation.ProfileID != mutation.ProfileID || operation.RequestID != mutation.RequestID || operation.Kind != mutation.Kind) {
			return nil, unavailable("OPERATION_MISMATCH", "The service acknowledgement did not match the submitted operation.")
		}
		return operation, clientFailure(err)
	case "workspace.read":
		return d.readWorkspace(ctx, raw)
	case "workspace.submit":
		return d.submitWorkspace(ctx, raw)
	}
	return nil, unavailable("METHOD_NOT_FOUND", "Client method is unavailable.")
}

func validDesktopStart(start *serviceprotocol.StartPayload) bool {
	if start == nil {
		return true
	}
	if platform.WindowsClientValidationOnly {
		return start.Mode == "validation" && start.ValidationSeconds >= 1 && start.ValidationSeconds <= 2700
	}
	return start.Mode == "daily" && start.ValidationSeconds == 0
}
func (d *Desktop) readWorkspace(ctx context.Context, raw json.RawMessage) (any, error) {
	var p workspaceRead
	if clientDecode(raw, &p) != nil || p.ProfileID != d.ClientProfileID() || len(p.PolicyJSON) > 65536 || len(p.Target) > 253 {
		return nil, unavailable("INVALID_PARAMS", "Invalid bounded workspace read.")
	}
	command := app.DesktopCommands{Profile: d.Profile, Runtime: d.Runtime}
	var result any
	var err error
	switch p.Action {
	case "document":
		if !onlyClientKeys(raw, "profile_id", "action") {
			break
		}
		result, err = command.Document(ctx)
	case "validate":
		if !onlyClientKeys(raw, "profile_id", "action", "policy_json") {
			break
		}
		result, err = command.ValidateDraft(ctx, []byte(p.PolicyJSON))
	case "diff":
		if !onlyClientKeys(raw, "profile_id", "action", "policy_json") {
			break
		}
		result, err = command.DiffDraft(ctx, []byte(p.PolicyJSON))
	case "history":
		if !onlyClientKeys(raw, "profile_id", "action") {
			break
		}
		result, err = command.History(ctx)
	case "explain":
		if !onlyClientKeys(raw, "profile_id", "action", "target") || p.Target == "" {
			break
		}
		result, err = command.Explain(ctx, p.Target)
	case "diagnostics":
		if !onlyClientKeys(raw, "profile_id", "action") {
			break
		}
		result, err = command.Diagnostics(ctx)
	case "cleanup_preview":
		if !onlyClientKeys(raw, "profile_id", "action") {
			break
		}
		result, err = command.CleanupPreview(ctx)
	case "recovery_entry":
		if !onlyClientKeys(raw, "profile_id", "action") {
			break
		}
		result, err = desktopRecoveryEntry()
	case "runtime":
		if !onlyClientKeys(raw, "profile_id", "action") {
			break
		}
		result, err = d.Environment(ctx)
	case "version":
		if !onlyClientKeys(raw, "profile_id", "action") {
			break
		}
		result = app.DesktopBuild()
	default:
		return nil, unavailable("INVALID_PARAMS", "Unknown workspace read.")
	}
	if result == nil && err == nil {
		return nil, unavailable("INVALID_PARAMS", "Invalid workspace fields.")
	}
	// Policy validation errors carry schema locations, never rejected values.
	// Returning them as a product DTO makes draft correction possible while
	// keeping filesystem, authentication and other raw errors private.
	var invalid *policy.ValidationError
	if (p.Action == "validate" || p.Action == "diff") && errors.As(err, &invalid) {
		return map[string]any{"profile_id": p.ProfileID, "valid": false, "validation": map[string]any{"field": invalid.Field, "message": invalid.Message, "line": invalid.Line, "column": invalid.Column}}, nil
	}
	if err != nil {
		return nil, clientFailure(err)
	}
	encoded, encodeErr := json.Marshal(result)
	var dto map[string]any
	if encodeErr != nil || json.Unmarshal(encoded, &dto) != nil || dto == nil {
		return nil, unavailable("INVALID_PROTOCOL", "Workspace result unavailable.")
	}
	dto["profile_id"] = p.ProfileID
	return dto, nil
}
func (d *Desktop) submitWorkspace(ctx context.Context, raw json.RawMessage) (any, error) {
	var p workspaceWrite
	if clientDecode(raw, &p) != nil || p.ProfileID != d.ClientProfileID() || !serviceprotocol.ValidID(p.RequestID) || len(p.PolicyJSON) > 65536 || len(p.BootstrapJSON) > 65536 || len(p.Content) > 700000 || len(p.SourcesJSON) > 65536 {
		return nil, unavailable("INVALID_PARAMS", "Invalid bounded workspace command.")
	}
	allowed := []string{"action", "request_id", "profile_id"}
	switch p.Action {
	case "initialize":
		allowed = append(allowed, "policy_json", "bootstrap_json")
	case "apply":
		allowed = append(allowed, "policy_json", "expected_revision")
	case "rollback":
		allowed = append(allowed, "revision", "expected_revision")
	case "import_nodes":
		allowed = append(allowed, "content")
	case "sync":
	case "cleanup":
		allowed = append(allowed, "opaque_run_id")
		if !serviceprotocol.ValidID(p.OpaqueRunID) {
			return nil, unavailable("INVALID_PARAMS", "Invalid run identifier.")
		}
	case "sources_save":
		allowed = append(allowed, "sources_json", "expected_revision")
	default:
		return nil, unavailable("INVALID_PARAMS", "Unknown workspace command.")
	}
	if !onlyClientKeys(raw, allowed...) {
		return nil, unavailable("INVALID_PARAMS", "Unexpected workspace fields.")
	}
	if (p.Action == "apply" || p.Action == "rollback" || p.Action == "sources_save") && (len(p.ExpectedRevision) == 0 || len(p.ExpectedRevision) > 128) || len(p.Revision) > 128 {
		return nil, unavailable("INVALID_PARAMS", "A bounded revision precondition is required.")
	}
	snapshot, err := d.Control.Snapshot(ctx, d.ClientProfileID())
	if err != nil {
		return nil, clientFailure(err)
	}
	if snapshot.ProfileID != d.ClientProfileID() {
		return nil, unavailable("PROFILE_MISMATCH", "The service profile did not match the selected workspace.")
	}
	if snapshot.ServiceState != "available" {
		return nil, unavailable("SERVICE_UNAVAILABLE", "The service is not available for workspace changes.")
	}
	// The service owns the asynchronous operation. The UI bridge never creates a worker.
	workspace := &serviceprotocol.WorkspacePayload{Action: p.Action, PolicyJSON: json.RawMessage(p.PolicyJSON), BootstrapJSON: json.RawMessage(p.BootstrapJSON), ExpectedPolicyRevision: p.ExpectedRevision, Revision: p.Revision, Content: p.Content, OpaqueRunID: p.OpaqueRunID, SourcesJSON: json.RawMessage(p.SourcesJSON)}
	mutation := serviceprotocol.Mutation{RequestID: p.RequestID, ProfileID: d.ClientProfileID(), ExpectedRevision: snapshot.Revision, RunRef: snapshot.RunRef, Kind: serviceprotocol.Workspace, Workspace: workspace}
	if mutation.Validate() != nil {
		return nil, unavailable("INVALID_PARAMS", "Workspace command is not supported by the service contract.")
	}
	operation, err := d.Control.Submit(ctx, mutation)
	if err == nil && (operation.ProfileID != mutation.ProfileID || operation.RequestID != mutation.RequestID || operation.Kind != mutation.Kind) {
		return nil, unavailable("OPERATION_MISMATCH", "The service acknowledgement did not match the submitted operation.")
	}
	return operation, clientFailure(err)
}
