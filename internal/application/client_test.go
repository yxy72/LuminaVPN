package application

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"netlaunch/internal/platform"
	p "netlaunch/internal/serviceprotocol"
	"netlaunch/internal/testutil"
)

type clientMock struct {
	profile     string
	calls       int
	last        p.Mutation
	response    p.Operation
	snapshot    *p.Snapshot
	failure     error
	unavailable bool
}

func scopedWorkspaceJSON(d *Desktop, raw string) json.RawMessage {
	var value map[string]any
	_ = json.Unmarshal([]byte(raw), &value)
	value["profile_id"] = d.ClientProfileID()
	encoded, _ := json.Marshal(value)
	return encoded
}

func (m *clientMock) Snapshot(context.Context, string) (p.Snapshot, error) {
	if m.snapshot != nil {
		return *m.snapshot, m.failure
	}
	state := "available"
	if m.unavailable {
		state = "not_installed"
	}
	return p.Snapshot{ProtocolVersion: 1, ServiceState: state, ProfileID: m.profile, Revision: 7, RunRef: "run", Restored: true}, m.failure
}
func (m *clientMock) Submit(_ context.Context, request p.Mutation) (p.Operation, error) {
	m.calls++
	m.last = request
	return p.Operation{ID: "operation", ProfileID: request.ProfileID, RequestID: request.RequestID, Kind: request.Kind}, m.failure
}
func (m *clientMock) Operation(context.Context, string) (p.Operation, error) {
	return m.response, m.failure
}
func mockClient(t *testing.T) (*Desktop, *clientMock) {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only client gate")
	}
	d := &Desktop{Profile: testutil.PrivateTempDir(t)}
	m := &clientMock{profile: d.ClientProfileID()}
	d.Control = m
	return d, m
}

func TestClientSubmissionIsTypedProfileBoundAndServiceOwned(t *testing.T) {
	d, m := mockClient(t)
	start := map[string]any{"mode": "daily", "channels": map[string]bool{"company": false, "personal": true}}
	if platform.WindowsClientValidationOnly {
		start["mode"] = "validation"
		start["validation_seconds"] = 1
	}
	raw, _ := json.Marshal(map[string]any{"request_id": "request", "profile_id": d.ClientProfileID(), "expected_revision": 7, "kind": "takeover_start", "start": start})
	if _, err := d.ClientRequest(context.Background(), "service.submit", raw); err != nil || m.calls != 1 {
		t.Fatal("typed request rejected", err)
	}
	for _, raw := range []string{
		`{"request_id":"r","profile_id":"other","expected_revision":0,"kind":"exit_restore","stop":{}}`,
		`{"request_id":"r","profile_id":"` + d.ClientProfileID() + `","expected_revision":0,"kind":"exit_restore","stop":{},"shell":"private-canary"}`,
		`{"request_id":"r","profile_id":"` + d.ClientProfileID() + `","expected_revision":0,"kind":"takeover_start","start":{"channels":{"company":false,"personal":true},"mode":"validation","validation_seconds":2701}}`,
	} {
		if _, err := d.ClientRequest(context.Background(), "service.submit", json.RawMessage(raw)); err == nil {
			t.Fatal("unbounded request accepted")
		}
	}
	if m.calls != 1 {
		t.Fatal("rejected request reached service")
	}
}

func TestDesktopStartRespectsCompiledValidationBoundary(t *testing.T) {
	daily := &p.StartPayload{Mode: "daily"}
	validation := &p.StartPayload{Mode: "validation", ValidationSeconds: 2700}
	if validDesktopStart(daily) == platform.WindowsClientValidationOnly || validDesktopStart(validation) != platform.WindowsClientValidationOnly {
		t.Fatal("compiled run mode gate widened")
	}
	for _, seconds := range []int{0, -1, 2701} {
		if validDesktopStart(&p.StartPayload{Mode: "validation", ValidationSeconds: seconds}) {
			t.Fatal("invalid validation duration accepted")
		}
	}
}
func TestWorkspaceUsesRawJSONAndRevisionInsideServiceOperation(t *testing.T) {
	d, m := mockClient(t)
	_, err := d.ClientRequest(context.Background(), "workspace.submit", scopedWorkspaceJSON(d, `{"request_id":"request","action":"apply","policy_json":"{\"version\":1}","expected_revision":"policy-revision"}`))
	if err != nil || m.calls != 1 || m.last.Kind != p.Workspace || string(m.last.Workspace.PolicyJSON) != `{"version":1}` || m.last.Workspace.ExpectedPolicyRevision != "policy-revision" || m.last.ExpectedRevision != 7 || m.last.RunRef != "run" {
		t.Fatal("workspace envelope drift", err)
	}
	_, err = d.ClientRequest(context.Background(), "workspace.submit", scopedWorkspaceJSON(d, `{"request_id":"request","action":"sources_save","sources_json":"{}"}`))
	if err == nil || m.calls != 1 {
		t.Fatal("missing source revision accepted")
	}
	m.unavailable = true
	_, err = d.ClientRequest(context.Background(), "workspace.submit", scopedWorkspaceJSON(d, `{"request_id":"another","action":"sync"}`))
	if err == nil || m.calls != 1 {
		t.Fatal("unavailable service received a workspace mutation")
	}
}
func TestClientProfileAndFailureProjectionNeverEchoPrivateDetails(t *testing.T) {
	d, m := mockClient(t)
	m.response = p.Operation{ID: "op", ProfileID: "other"}
	if _, err := d.ClientRequest(context.Background(), "service.operation", json.RawMessage(`{"operation_id":"op"}`)); err == nil {
		t.Fatal("cross profile operation accepted")
	}
	m.profile = "other"
	if _, err := d.ClientRequest(context.Background(), "service.snapshot", json.RawMessage(`{}`)); err == nil {
		t.Fatal("cross profile state accepted")
	}
	m.failure = errors.New("private-canary")
	_, err := d.ClientRequest(context.Background(), "service.snapshot", json.RawMessage(`{}`))
	if err == nil || strings.Contains(err.Error(), "private-canary") {
		t.Fatal("private backend failure leaked")
	}
	d.Control = nil
	if _, err := d.ClientRequest(context.Background(), "workspace.read", scopedWorkspaceJSON(d, `{"action":"document"}`)); err == nil {
		t.Fatal("offline mutation gate missing")
	}
}

func TestServiceDiagnosticsIsBoundToTheSelectedRunAndOmitsPrivateFields(t *testing.T) {
	d := &Desktop{Profile: testutil.PrivateTempDir(t)}
	view := p.Snapshot{
		ProfileID: d.ClientProfileID(), RunRef: "run-7", ServiceState: "available", TakeoverState: "managed",
		Direct: &p.Channel{Desired: true, State: "ready", Route: "direct", Probe: &p.RouteProbe{
			Scope: "system_tun", PathState: "verified", ServiceState: "healthy", CheckedAt: time.Now(),
		}},
		Company:   p.Channel{State: "unknown", Route: "unknown", Reason: "private-hostname"},
		Personal:  p.Channel{State: "unknown", Route: "unknown", Health: &p.HealthRound{Epoch: "private-epoch"}},
		Challenge: &p.Challenge{ID: "private-challenge"},
		Settings:  &p.SettingsPayload{OfficeOverrides: []p.Override{{Value: "private-domain.test"}}},
	}
	d.Control = &clientMock{snapshot: &view}
	read := func() (any, error) {
		if runtime.GOOS == "windows" {
			return d.ClientRequest(t.Context(), "workspace.read", scopedWorkspaceJSON(d, `{"action":"diagnostics"}`))
		}
		return d.serviceDiagnostics(t.Context())
	}
	report, err := read()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(report)
	if err != nil || strings.Contains(string(data), "private") {
		t.Fatal("unexpected diagnostics data", err)
	}
	var fields struct {
		ProfileID string                       `json:"profile_id"`
		RunRef    string                       `json:"run_ref"`
		Source    string                       `json:"source"`
		Channels  map[string]diagnosticChannel `json:"channels"`
	}
	if err = json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if fields.ProfileID != view.ProfileID || fields.RunRef != view.RunRef || fields.Source != "windows_service" || len(fields.Channels) != 3 || fields.Channels["direct"].Probe == nil || fields.Channels["direct"].Probe.Scope != "system_tun" {
		t.Fatal("missing service run evidence")
	}
	view.ProfileID = "other"
	if _, err = read(); err == nil {
		t.Fatal("foreign service run was exported")
	}
}

func TestWorkspaceDraftValidationReturnsOnlySchemaLocation(t *testing.T) {
	d, _ := mockClient(t)
	value, err := d.ClientRequest(context.Background(), "workspace.read", scopedWorkspaceJSON(d, `{"action":"validate","policy_json":"{\"private-canary\":true}"}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(value)
	if strings.Contains(string(raw), "private-canary") || !strings.Contains(string(raw), `"valid":false`) || !strings.Contains(string(raw), `"field":"policy"`) {
		t.Fatal("draft location disclosure contract")
	}
}
func TestWorkspaceCannotFollowStableAPIAcrossProfiles(t *testing.T) {
	d, m := mockClient(t)
	for _, method := range []string{"workspace.read", "workspace.submit"} {
		raw := json.RawMessage(`{"profile_id":"old-profile","action":"document"}`)
		if method == "workspace.submit" {
			raw = json.RawMessage(`{"profile_id":"old-profile","request_id":"old-request","action":"sync"}`)
		}
		if _, err := d.ClientRequest(context.Background(), method, raw); err == nil {
			t.Fatal("old profile request followed the current facade")
		}
	}
	if m.calls != 0 {
		t.Fatal("cross-profile write reached service")
	}
}
