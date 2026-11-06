package winservice

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"time"

	p "netlaunch/internal/serviceprotocol"
)

// UserAuthEvent is private fixed-worker data. Session is consumed by the
// service in memory and must never be copied to a public snapshot or ledger.
type UserAuthEvent struct {
	Version         int             `json:"version"`
	Kind            string          `json:"kind"`
	ChallengeID     string          `json:"challenge_id,omitempty"`
	Sequence        uint64          `json:"sequence,omitempty"`
	ChallengeKind   string          `json:"challenge_kind,omitempty"`
	ChallengeFields []p.AuthField   `json:"challenge_fields,omitempty"`
	Expires         time.Time       `json:"expires_at,omitempty"`
	Session         json.RawMessage `json:"session,omitempty"`
	Code            string          `json:"code,omitempty"`
}
type UserAuthResponse = p.AuthPayload

type UserAuthNetworkBinding struct {
	GUID       string `json:"guid"`
	LUID       uint64 `json:"luid"`
	Index      uint32 `json:"index"`
	Address    string `json:"address"`
	Gateway    string `json:"gateway"`
	Generation string `json:"generation"`
}

var authGUID = regexp.MustCompile(`^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$`)

func (n UserAuthNetworkBinding) Validate() error {
	address, e1 := netip.ParseAddr(n.Address)
	gateway, e2 := netip.ParseAddr(n.Gateway)
	if !authGUID.MatchString(n.GUID) || n.GUID == "{00000000-0000-0000-0000-000000000000}" || n.LUID == 0 || n.Index == 0 || !digestText.MatchString(n.Generation) || e1 != nil || e2 != nil || !address.Is4() || !gateway.Is4() || address.IsUnspecified() || gateway.IsUnspecified() || address.IsMulticast() || gateway.IsMulticast() || address.IsLoopback() || gateway.IsLoopback() {
		return errors.New("verified private physical plan required")
	}
	return nil
}

func (e UserAuthEvent) Validate() error {
	if e.Version != 1 {
		return errors.New("unsupported private auth protocol")
	}
	switch e.Kind {
	case "challenge":
		if !p.ValidID(e.ChallengeID) || e.Sequence == 0 || e.Expires.IsZero() || len(e.Session) > 0 || e.Code != "" || len(e.ChallengeFields) > 16 {
			return errors.New("invalid private challenge")
		}
		if e.ChallengeKind != "username" && e.ChallengeKind != "password" && e.ChallengeKind != "otp" && e.ChallengeKind != "form" {
			return errors.New("unsupported private challenge type")
		}
		if e.ChallengeKind == "form" && len(e.ChallengeFields) == 0 {
			return errors.New("empty private form")
		}
		seen := map[string]bool{}
		for _, field := range e.ChallengeFields {
			if !p.ValidID(field.FieldID) || seen[field.FieldID] || len(field.LabelCode) > 64 || (field.LabelCode != "" && !p.ValidID(field.LabelCode)) || len(field.Choices) > 64 {
				return errors.New("invalid private field")
			}
			seen[field.FieldID] = true
			if field.Kind != "username" && field.Kind != "password" && field.Kind != "otp" && field.Kind != "text" && field.Kind != "select" {
				return errors.New("unsupported private field type")
			}
			if (field.Kind == "select") != (len(field.Choices) > 0) {
				return errors.New("invalid private field choices")
			}
			choices := map[string]bool{}
			for _, choice := range field.Choices {
				if !p.ValidID(choice.ChoiceID) || choices[choice.ChoiceID] || len(choice.Label) > 128 || strings.ContainsAny(choice.Label, "\x00\r\n") {
					return errors.New("invalid private choice")
				}
				choices[choice.ChoiceID] = true
			}
		}
	case "complete":
		session := bytes.TrimSpace(e.Session)
		if e.ChallengeID != "" || len(e.ChallengeFields) > 0 || e.ChallengeKind != "" || !e.Expires.IsZero() || e.Code != "" || len(session) < 2 || session[0] != '{' || len(e.Session) > 64<<10 || !json.Valid(e.Session) {
			return errors.New("invalid private session completion")
		}
	case "failed":
		if !p.ValidID(e.Code) || len(e.Session) > 0 || e.ChallengeID != "" || len(e.ChallengeFields) > 0 || e.ChallengeKind != "" || !e.Expires.IsZero() {
			return errors.New("invalid private auth failure")
		}
	default:
		return errors.New("unsupported private auth event")
	}
	return nil
}

func validateAuthResponse(event UserAuthEvent, response UserAuthResponse, now time.Time) error {
	if response.Validate() != nil || event.Kind != "challenge" || event.ChallengeID != response.ChallengeID || event.Sequence != response.Sequence || !now.Before(event.Expires) {
		return errors.New("response does not match the live private challenge")
	}
	if len(event.ChallengeFields) == 0 {
		if len(response.Fields) > 0 {
			return errors.New("unexpected form values")
		}
		switch event.ChallengeKind {
		case "username":
			if response.Username != "" && response.Password+response.OTP == "" {
				return nil
			}
		case "password":
			if response.Password != "" && response.Username+response.OTP == "" {
				return nil
			}
		case "otp":
			if response.OTP != "" && response.Username+response.Password == "" {
				return nil
			}
		}
		return errors.New("response type does not match the native field")
	}
	if len(response.Fields) != len(event.ChallengeFields) || response.Username+response.Password+response.OTP != "" {
		return errors.New("response is not the complete live field set")
	}
	values := map[string]string{}
	for _, field := range response.Fields {
		values[field.FieldID] = field.Value
	}
	for _, field := range event.ChallengeFields {
		value, ok := values[field.FieldID]
		if !ok {
			return errors.New("unknown or missing form field")
		}
		if field.Kind == "select" {
			found := false
			for _, choice := range field.Choices {
				found = found || choice.ChoiceID == value
			}
			if !found {
				return errors.New("unknown live form choice")
			}
		}
	}
	return nil
}
