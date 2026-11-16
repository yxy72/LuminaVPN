package desktopbridge

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netlaunch/internal/app"
	"netlaunch/internal/policy"
	p "netlaunch/internal/serviceprotocol"
)

func TestMacWorkspaceEditsThroughDesktopBridge(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	s.Service.EnableLocalWorkspace(ctx)
	t.Cleanup(s.Service.CloseLocalWorkspace)
	request := func(method string, params any) Response {
		t.Helper()
		raw, err := json.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		return s.respond(ctx, Request{ID: "test", Method: method, Params: raw})
	}
	hello := request("session.hello", map[string]any{"protocol_major": ProtocolMajor})
	if hello.Error != nil {
		t.Fatal(hello.Error)
	}
	caps := hello.Result.(map[string]any)["capabilities"].(map[string]any)
	if caps["config_write"] != true || caps["read_only"] != false || caps["connection_start"] != false || caps["connection_stop"] != false || caps["windows_client"] != false {
		t.Fatal(caps)
	}
	if response := request("service.snapshot", map[string]any{}); response.Error == nil || response.Error.Code != "CLIENT_UNAVAILABLE" {
		t.Fatalf("unexpected network service response: %#v", response)
	}
	if _, err := os.Stat(s.Service.Profile); !os.IsNotExist(err) {
		t.Fatal("the handshake created a local profile")
	}
	var config policy.Config
	if err := json.Unmarshal([]byte(app.Example), &config); err != nil {
		t.Fatal(err)
	}
	config.Company, config.Personal = policy.Channel{}, policy.Channel{}
	config.VPN, config.Probes = policy.VPN{}, nil
	profile := s.Service.ClientProfileID()
	submit := func(id string, body map[string]any) p.Operation {
		t.Helper()
		body["request_id"] = id
		body["profile_id"] = profile
		r := request("workspace.submit", body)
		if r.Error != nil {
			t.Fatal(r.Error)
		}
		first := r.Result.(p.Operation)
		if first.RequestID != id || first.ProfileID != profile || first.Kind != p.Workspace {
			t.Fatal(first)
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			r = request("service.operation", map[string]string{"operation_id": first.ID})
			if r.Error != nil {
				t.Fatal(r.Error)
			}
			op := r.Result.(p.Operation)
			if op.Completed {
				return op
			}
			if time.Now().After(deadline) {
				t.Fatalf("edit did not complete: %#v", op)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	policyText := func() string {
		b, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	readDocument := func() map[string]any {
		t.Helper()
		r := request("workspace.read", map[string]any{"profile_id": profile, "action": "document"})
		if r.Error != nil {
			t.Fatal(r.Error)
		}
		return r.Result.(map[string]any)
	}
	if op := submit("first", map[string]any{"action": "initialize", "policy_json": policyText()}); op.Error != nil {
		t.Fatal(op.Error)
	}
	oldRevision := readDocument()["revision"]
	config.Ports.Proxy++
	if op := submit("edit", map[string]any{"action": "apply", "policy_json": policyText(), "expected_revision": oldRevision}); op.Error != nil {
		t.Fatal(op.Error)
	}
	newRevision := readDocument()["revision"]
	if newRevision == nil || newRevision == oldRevision {
		t.Fatal("edit did not publish a new revision")
	}
	config.Ports.Proxy++
	if op := submit("stale", map[string]any{"action": "apply", "policy_json": policyText(), "expected_revision": oldRevision}); op.Error == nil || readDocument()["revision"] != newRevision {
		t.Fatal("stale draft modified the saved profile")
	}
	if _, err := os.Stat(filepath.Join(s.Service.Profile, "runs")); !os.IsNotExist(err) {
		t.Fatal("configuring a profile created a network run")
	}
}
