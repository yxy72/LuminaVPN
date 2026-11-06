//go:build windows

package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"netlaunch/internal/auth"
	"netlaunch/internal/policy"
	p "netlaunch/internal/serviceprotocol"
	"netlaunch/internal/winservice"
)

type fakeStructuredAuth struct {
	run func(context.Context, policy.VPN, func([]p.AuthField) ([]p.AuthFieldValue, error)) (auth.Session, error)
}

func (f fakeStructuredAuth) Authenticate(ctx context.Context, vpn policy.VPN, prompt func([]p.AuthField) ([]p.AuthFieldValue, error)) (auth.Session, error) {
	return f.run(ctx, vpn, prompt)
}
func TestNativeAuthPublicAMD64LayoutAndUnknownFormsFailClosed(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("reviewed amd64 ABI")
	}
	if unsafe.Sizeof(ocOption{}) != 56 || unsafe.Offsetof(ocOption{}.Name) != 16 || unsafe.Offsetof(ocOption{}.Flags) != 40 || unsafe.Offsetof(ocOption{}.Reserved) != 48 || unsafe.Sizeof(ocSelect{}) != 72 || unsafe.Offsetof(ocSelect{}.Choices) != 64 || unsafe.Sizeof(ocForm{}) != 72 || unsafe.Offsetof(ocForm{}.Options) != 48 || unsafe.Offsetof(ocForm{}.AuthGroupSelection) != 64 {
		t.Fatal("OpenConnect API5 public layout drift")
	}
	username := make([]byte, 129)
	copy(username, "username")
	password := make([]byte, 129)
	copy(password, "Password:")
	first, second := &ocOption{Type: 1}, &ocOption{Type: 2}
	var pin runtime.Pinner
	pin.Pin(first)
	pin.Pin(second)
	pin.Pin(&username[0])
	pin.Pin(&password[0])
	defer pin.Unpin()
	first.Name = uintptr(unsafe.Pointer(&username[0]))
	first.Next = uintptr(unsafe.Pointer(second))
	second.Label = uintptr(unsafe.Pointer(&password[0]))
	form := &ocForm{Options: uintptr(unsafe.Pointer(first))}
	pin.Pin(form)
	fields, bindings, err := nativeFormFields(uintptr(unsafe.Pointer(form)))
	if err != nil || len(fields) != 2 || fields[0].Kind != "username" || fields[1].Kind != "password" || bindings["f1"].pointer != uintptr(unsafe.Pointer(second)) {
		t.Fatal("native option identity lost")
	}
	second.Type = 6
	if _, _, err := nativeFormFields(uintptr(unsafe.Pointer(form))); err == nil {
		t.Fatal("SSO form was accepted")
	}
	second.Type = 2
	copy(password, "unreviewed private prompt\x00")
	if _, _, err := nativeFormFields(uintptr(unsafe.Pointer(form))); err == nil {
		t.Fatal("unknown password prompt was accepted")
	}
	first.Next = uintptr(unsafe.Pointer(first))
	if _, _, err := nativeFormFields(uintptr(unsafe.Pointer(form))); err == nil {
		t.Fatal("cyclic option list was accepted")
	}
	runtime.KeepAlive([]any{username, password, first, second, form})
}
func TestPrivateStructuredAuthMatchesFieldsAndNeverGuessesOTPOrder(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact", true: "stale_sequence"}[stale], func(t *testing.T) {
			input, inputWriter := io.Pipe()
			output, outputWriter := io.Pipe()
			defer input.Close()
			defer inputWriter.Close()
			defer output.Close()
			defer outputWriter.Close()
			saved := false
			cfg := policy.Config{VPN: policy.VPN{Server: "https://vpn.example.test", EndpointIPv4: "192.0.2.1"}}
			deps := serviceAuthDependencies{now: time.Now, save: func(string, policy.VPN, auth.Session) error { saved = true; return nil }, engine: func(winservice.UserAuthNetworkBinding) (serviceAuthEngine, error) {
				return fakeStructuredAuth{run: func(ctx context.Context, vpn policy.VPN, prompt func([]p.AuthField) ([]p.AuthFieldValue, error)) (auth.Session, error) {
					values, err := prompt([]p.AuthField{{FieldID: "f0", Kind: "username", LabelCode: "ACCOUNT"}, {FieldID: "f1", Kind: "password", LabelCode: "SECRET"}, {FieldID: "f2", Kind: "otp", LabelCode: "OTP"}})
					if err != nil {
						return auth.Session{}, err
					}
					fields := map[string]string{}
					for _, v := range values {
						fields[v.FieldID] = v.Value
					}
					if fields["f1"] != "password-canary" || fields["f2"] != "otp-canary" {
						return auth.Session{}, errors.New("field identity mismatch")
					}
					return auth.Session{Cookie: "private-session-canary", Host: "vpn.example.test", Fingerprint: "sha256:AA==", Created: time.Now()}, nil
				}}, nil
			}}
			done := make(chan error, 1)
			go func() {
				done <- authenticatePrivateStream(bufio.NewScanner(input), outputWriter, "unused-private-profile", cfg, deps)
			}()
			decoder := json.NewDecoder(output)
			var event winservice.UserAuthEvent
			if decoder.Decode(&event) != nil || event.Validate() != nil || event.Kind != "challenge" {
				t.Fatal("native challenge frame unavailable")
			}
			response := p.AuthPayload{ChallengeID: event.ChallengeID, Sequence: event.Sequence, Fields: []p.AuthFieldValue{{FieldID: "f2", Value: "otp-canary"}, {FieldID: "f0", Value: "user-canary"}, {FieldID: "f1", Value: "password-canary"}}}
			if stale {
				response.Sequence++
			}
			if json.NewEncoder(inputWriter).Encode(response) != nil {
				t.Fatal("private response unavailable")
			}
			var terminal winservice.UserAuthEvent
			if decoder.Decode(&terminal) != nil || terminal.Validate() != nil {
				t.Fatal("private terminal frame invalid")
			}
			select {
			case err := <-done:
				if stale {
					if err == nil || saved || terminal.Kind != "failed" {
						t.Fatal("stale response passed authentication")
					}
				} else if err != nil || !saved || terminal.Kind != "complete" {
					t.Fatal("exact private authentication failed", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("private authentication fixture did not finish")
			}
		})
	}
}
