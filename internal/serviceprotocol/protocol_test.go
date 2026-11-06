package serviceprotocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExplicitDailyAndBoundedValidationModes(t *testing.T) {
	for _, value := range []struct {
		mode    string
		seconds int
		ok      bool
	}{{"daily", 0, true}, {"daily", 1, false}, {"validation", 1, true}, {"validation", 2700, true}, {"validation", 2701, false}, {"validation", 0, false}, {"legacy_home", 0, false}, {"", 0, false}} {
		m := Mutation{RequestID: "request", ProfileID: "profile", Kind: TakeoverStart, Start: &StartPayload{Mode: value.mode, ValidationSeconds: value.seconds}}
		if (m.Validate() == nil) != value.ok {
			t.Fatalf("mode=%s seconds=%d", value.mode, value.seconds)
		}
	}
}
func TestTypedKindsRejectShellPathsAndExtraPayloads(t *testing.T) {
	for _, body := range []string{`{"version":1,"method":"exec","argv":["cmd.exe"]}`, `{"version":1,"method":"submit","mutation":{"request_id":"r","profile_id":"p","kind":"takeover_stop","stop":{},"exe":"foreign.exe"}}`, `{"version":1,"method":"submit","mutation":{"request_id":"r","profile_id":"../p","kind":"takeover_stop","stop":{}}}`} {
		if _, err := DecodeRequest([]byte(body)); err == nil {
			t.Fatal("unbounded request accepted")
		}
	}
	m := Mutation{RequestID: "r", ProfileID: "p", Kind: TakeoverStop, Stop: &StopPayload{}, Start: &StartPayload{Mode: "daily"}}
	if m.Validate() == nil {
		t.Fatal("ambiguous mutation accepted")
	}
}
func TestWorkspaceActionFieldsAndExactlyOneInitializer(t *testing.T) {
	for _, w := range []WorkspacePayload{{Action: "initialize", PolicyJSON: json.RawMessage(`{}`)}, {Action: "initialize", BootstrapJSON: json.RawMessage(`{}`)}, {Action: "sources_save", SourcesJSON: json.RawMessage(`[]`)}} {
		if err := w.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, w := range []WorkspacePayload{{Action: "initialize"}, {Action: "initialize", PolicyJSON: json.RawMessage(`{}`), BootstrapJSON: json.RawMessage(`{}`)}, {Action: "sync", Content: "unapproved"}, {Action: "cleanup", OpaqueRunID: "../foreign"}, {Action: "sources_save", Content: "not typed sources json"}, {Action: "import_nodes", Content: strings.Repeat("x", 701<<10)}} {
		if w.Validate() == nil {
			t.Fatalf("invalid workspace action accepted: %s", w.Action)
		}
	}
}
func TestSnapshotEmptySettingsAreArraysAndNoCompanyOverride(t *testing.T) {
	raw, err := json.Marshal(SettingsPayload{Environment: "office"})
	if err != nil || !strings.Contains(string(raw), `"office_overrides":[]`) || !strings.Contains(string(raw), `"home_overrides":[]`) {
		t.Fatalf("invalid default settings: %s %v", raw, err)
	}
	m := Mutation{RequestID: "r", ProfileID: "p", Kind: SettingsApply, Settings: &SettingsPayload{Environment: "home", HomeOverrides: []Override{{Type: "domain", Value: "corp.example", Target: "company"}}}}
	if m.Validate() == nil {
		t.Fatal("override elevated company authorization")
	}
}
