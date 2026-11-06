package desktopbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netlaunch/internal/application"
	"netlaunch/internal/testutil"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	root := testutil.PrivateTempDir(t)
	service, err := application.NewDesktop(filepath.Join(root, "missing-profile"), filepath.Join(root, "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	service.Control = nil // Exercise the unchanged offline contract with no real service.
	return &Server{Service: service}
}

func exchange(t *testing.T, s *Server, input string) []Response {
	t.Helper()
	var output bytes.Buffer
	if err := s.Serve(context.Background(), strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	responses := []Response{}
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		if line == "" {
			continue
		}
		var r Response
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal("stdout contains non-protocol data", err)
		}
		responses = append(responses, r)
	}
	return responses
}

func TestHandshakeAndReadOnlyCapabilities(t *testing.T) {
	s := testServer(t)
	responses := exchange(t, s, "{\"id\":\"1\",\"method\":\"state.get\"}\n{\"id\":\"2\",\"method\":\"session.hello\",\"params\":{\"protocol_major\":1}}\n{\"id\":\"3\",\"method\":\"state.get\"}\n{\"id\":\"4\",\"method\":\"connection.start\"}\n")
	if len(responses) != 4 || responses[0].Error.Code != "HANDSHAKE_REQUIRED" || responses[1].Error != nil || responses[2].Error != nil || responses[3].Error.Code != "METHOD_NOT_FOUND" {
		t.Fatal(responses)
	}
	hello := responses[1].Result.(map[string]any)
	caps := hello["capabilities"].(map[string]any)
	if caps["connection_start"] != false || caps["connection_stop"] != false || caps["config_write"] != false || caps["read_only"] != true {
		t.Fatal(caps)
	}
	methods, ok := caps["methods"].([]any)
	if !ok || len(methods) != 8 || caps["windows_client"] != false {
		t.Fatal("offline handshake widened its method group")
	}
	for _, method := range methods {
		if name, ok := method.(string); !ok || application.IsClientMethod(name) {
			t.Fatal("client request leaked into offline method group")
		}
	}
	if _, err := os.Stat(s.Service.Profile); !os.IsNotExist(err) {
		t.Fatal("readonly protocol created profile")
	}
}

func TestSharedTypeScriptContract(t *testing.T) {
	if len(Methods) != 8 || len(application.ClientMethods) != 5 {
		t.Fatal("read and client method groups must remain separate")
	}
	// The public fixture and schema are consumed by both languages, catching
	// envelope drift without generating a second set of application types.
	raw, err := os.ReadFile("../../desktop/protocol/fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Hello Request           `json:"hello_request"`
		State application.State `json:"state"`
	}
	if err := strict(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Hello.ID == "" || fixture.State.RuntimeLiveness != "not_checked" || len(fixture.State.Status.Channels) != 3 {
		t.Fatal("shared desktop fixture contract drift")
	}
	encoded, _ := json.Marshal(fixture.Hello)
	responses := exchange(t, testServer(t), string(encoded)+"\n")
	if len(responses) != 1 || responses[0].Error != nil || responses[0].ID != fixture.Hello.ID {
		t.Fatal(responses)
	}
	var schema struct {
		Properties struct {
			Method struct {
				Enum []string `json:"enum"`
			} `json:"method"`
		} `json:"properties"`
	}
	raw, err = os.ReadFile("../../desktop/protocol/schema.json")
	if err != nil || json.Unmarshal(raw, &schema) != nil {
		t.Fatal("shared protocol schema unavailable")
	}
	expected := append(append([]string{}, Methods...), application.ClientMethods...)
	if len(schema.Properties.Method.Enum) != len(expected) {
		t.Fatal("shared method set drift")
	}
	for i, method := range expected {
		if schema.Properties.Method.Enum[i] != method {
			t.Fatal("shared method order drift")
		}
	}
}

func TestParameterAndFramingValidation(t *testing.T) {
	for _, tc := range []struct{ input, code string }{
		{`{"id":"x","method":"session.hello","extra":"private-canary"}`, "INVALID_REQUEST"},
		{`{"id":"x","method":"state.get","params":{"profile":"private-canary"}}`, "INVALID_PARAMS"},
		{`{"id":"x","method":"nodes.list","params":{"limit":101}}`, "INVALID_PARAMS"},
		{`{"id":"x","method":"nodes.list","params":{"offset":-1}}`, "INVALID_PARAMS"},
		{`{"id":"x","method":"config.get","params":{"limit":101}}`, "INVALID_PARAMS"},
		{`{"id":"x","method":"config.get","params":{"offset":50001}}`, "INVALID_PARAMS"},
		{`{"id":"x","method":"state.get","params":null}`, "INVALID_PARAMS"},
		{`{"id":"x","method":"state.get"} {"private":"canary"}`, "INVALID_REQUEST"},
		{strings.Repeat("x", MaxFrame+2), "FRAME_TOO_LARGE"},
	} {
		s := testServer(t)
		s.hello = true
		responses := exchange(t, s, tc.input+"\n")
		if len(responses) != 1 || responses[0].Error == nil || responses[0].Error.Code != tc.code {
			t.Fatal(tc.code, responses)
		}
		raw, _ := json.Marshal(responses)
		if bytes.Contains(raw, []byte("private-canary")) {
			t.Fatal("rejected payload disclosed")
		}
	}
}

func TestProtocolMismatchDoesNotEnableReads(t *testing.T) {
	responses := exchange(t, testServer(t), "{\"id\":\"1\",\"method\":\"session.hello\",\"params\":{\"protocol_major\":2}}\n{\"id\":\"2\",\"method\":\"state.get\"}\n")
	if responses[0].Error.Code != "PROTOCOL_MISMATCH" || responses[1].Error.Code != "HANDSHAKE_REQUIRED" {
		t.Fatal(responses)
	}
}

type brokenOutput struct{ writes int }

func (w *brokenOutput) Write(p []byte) (int, error) {
	w.writes++
	return 0, errors.New("broken private-output-canary")
}

func TestBrokenControlPipeEndsSessionWithoutActions(t *testing.T) {
	s := testServer(t)
	out := &brokenOutput{}
	input := "{\"id\":\"1\",\"method\":\"session.hello\"}\n{\"id\":\"2\",\"method\":\"state.get\"}\n"
	if err := s.Serve(context.Background(), strings.NewReader(input), out); err != nil || out.writes != 1 {
		t.Fatal(err, out.writes)
	}
	if _, err := os.Stat(s.Service.Profile); !os.IsNotExist(err) {
		t.Fatal("disconnected UI created profile")
	}
}
