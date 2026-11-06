//go:build windows

package app

import (
	"encoding/json"
	"strings"
	"testing"

	"netlaunch/internal/engine"
	"netlaunch/internal/policy"
	p "netlaunch/internal/serviceprotocol"
	"netlaunch/internal/winservice"
)

func TestServiceHelperTypedInputCannotSelectExecutionOrSecrets(t *testing.T) {
	for _, raw := range []string{
		`{"config":{},"executable":"C:\\untrusted.exe"}`,
		`{"config":{},"runtime":"C:\\untrusted"}`,
		`{"config":{},"profile_path":"C:\\untrusted"}`,
		`{"config":{},"password":"fixture"}`,
		`{"config":{},"otp":"fixture"}`,
		`{"config":{"vpn":{"password":"fixture"}}}`,
		`{"channels":{},"validation_seconds":2700}`,
		`{} {}`,
		strings.Repeat(" ", p.MaxFrame+1),
	} {
		var payload ServicePreparePayload
		if decodeServiceHelperJSON([]byte(raw), &payload) == nil {
			t.Fatal("untyped or oversized helper input accepted")
		}
	}
	var envelope serviceHelperEnvelope
	if decodeServiceHelperJSON([]byte(`{"action":"status","payload":{},"command":"anything"}`), &envelope) == nil {
		t.Fatal("helper envelope accepted a generic command")
	}
}

func TestServiceHelperFreshBindingPreservesExplicitDisabledChannels(t *testing.T) {
	input := ServicePreparePayload{Binding: winservice.Binding{ExecutorSID: "S-1-5-18", Mode: string(engine.Daily)}, Mode: engine.Daily, Channels: policy.ChannelIntent{}}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ServicePreparePayload
	if err = decodeServiceHelperJSON(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareServiceBinding(decoded)
	if err != nil || prepared.Channels != (policy.ChannelIntent{}) || prepared.Mode != engine.Daily {
		t.Fatal("both-off was replaced by a legacy default", err)
	}
	for _, alter := range []func(*ServicePreparePayload){
		func(v *ServicePreparePayload) { v.Binding.ExecutorSID = "S-1-5-21-1" },
		func(v *ServicePreparePayload) { v.Binding.Mode = "validation" },
		func(v *ServicePreparePayload) { v.Binding.PreparedRunID = "already-prepared" },
		func(v *ServicePreparePayload) { v.Binding.SpecDigest = strings.Repeat("a", 64) },
	} {
		bad := input
		alter(&bad)
		if _, err := prepareServiceBinding(bad); err == nil {
			t.Fatal("nonfresh or mismatched service binding accepted")
		}
	}
}
