package winservice

import (
	"strings"
	"testing"
	"time"

	p "netlaunch/internal/serviceprotocol"
)

func TestPrivateAuthResponseMustMatchExactLiveFormAndSequence(t *testing.T) {
	now := time.Now()
	event := UserAuthEvent{Version: 1, Kind: "challenge", ChallengeID: "challenge", Sequence: 2, ChallengeKind: "form", Expires: now.Add(time.Minute), ChallengeFields: []p.AuthField{{FieldID: "f0", Kind: "username"}, {FieldID: "f1", Kind: "password"}, {FieldID: "f2", Kind: "select", Choices: []p.AuthChoice{{ChoiceID: "c0", Label: "Example"}}}}}
	if event.Validate() != nil {
		t.Fatal("valid typed form rejected")
	}
	response := UserAuthResponse{ChallengeID: "challenge", Sequence: 2, Fields: []p.AuthFieldValue{{FieldID: "f0", Value: "example"}, {FieldID: "f1", Value: "transient-password"}, {FieldID: "f2", Value: "c0"}}}
	if validateAuthResponse(event, response, now) != nil {
		t.Fatal("exact live form rejected")
	}
	for _, change := range []func(*UserAuthResponse){func(r *UserAuthResponse) { r.Sequence = 1 }, func(r *UserAuthResponse) { r.ChallengeID = "other" }, func(r *UserAuthResponse) { r.Fields = r.Fields[:2] }, func(r *UserAuthResponse) { r.Fields[2].Value = "c1" }, func(r *UserAuthResponse) { r.Username = "mixed" }} {
		bad := response
		bad.Fields = append([]p.AuthFieldValue{}, response.Fields...)
		change(&bad)
		if validateAuthResponse(event, bad, now) == nil {
			t.Fatal("stale/partial/unknown form response accepted")
		}
	}
	if validateAuthResponse(event, response, event.Expires) == nil {
		t.Fatal("expired form accepted")
	}
}

func TestPrivateAuthCannotGuessPasswordOrOtpOrder(t *testing.T) {
	now := time.Now()
	event := UserAuthEvent{Version: 1, Kind: "challenge", ChallengeID: "challenge", Sequence: 1, ChallengeKind: "otp", Expires: now.Add(time.Minute)}
	if validateAuthResponse(event, UserAuthResponse{ChallengeID: "challenge", Sequence: 1, Password: "password"}, now) == nil {
		t.Fatal("password guessed for OTP challenge")
	}
	if validateAuthResponse(event, UserAuthResponse{ChallengeID: "challenge", Sequence: 1, OTP: "123456"}, now) != nil {
		t.Fatal("known OTP field rejected")
	}
	if (UserAuthEvent{Version: 1, Kind: "challenge", ChallengeKind: "console_prompt"}).Validate() == nil {
		t.Fatal("unsupported prompt type accepted")
	}
}
func TestPrivateAuthPhysicalPlanRequiresFullIdentityAndNetworkGeneration(t *testing.T) {
	plan := UserAuthNetworkBinding{GUID: "{11111111-2222-3333-4444-555555555555}", LUID: 123, Index: 2, Address: "192.0.2.2", Gateway: "192.0.2.1", Generation: strings.Repeat("a", 64)}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*UserAuthNetworkBinding){func(p *UserAuthNetworkBinding) { p.GUID = "{00000000-0000-0000-0000-000000000000}" }, func(p *UserAuthNetworkBinding) { p.LUID = 0 }, func(p *UserAuthNetworkBinding) { p.Index = 0 }, func(p *UserAuthNetworkBinding) { p.Address = "::1" }, func(p *UserAuthNetworkBinding) { p.Gateway = "0.0.0.0" }, func(p *UserAuthNetworkBinding) { p.Generation = "unknown" }} {
		bad := plan
		alter(&bad)
		if bad.Validate() == nil {
			t.Fatal("partial or unknown physical plan accepted")
		}
	}
}
