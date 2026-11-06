//go:build windows

package auth

import (
	"encoding/json"
	"errors"
	"netlaunch/internal/policy"
	"netlaunch/internal/usersession"
	"time"
)

const removeInvalidCache = true

func protectionPurpose(vpn policy.VPN) string { return "vpn/" + vpn.Server + "/" + vpn.EndpointIPv4 }

// EncodeRuntime protects only the existing validated session, never a password
// or OTP. The encrypted Created value is preserved; saving/reading cannot renew
// its two-hour absolute lifetime. It uses the current (possibly impersonated)
// Windows user, so service bootstrap must re-protect after obtaining user data.
func EncodeRuntime(vpn policy.VPN, s Session) (any, error) {
	if err := s.Validate(vpn); err != nil {
		return nil, err
	}
	if s.Created.IsZero() || s.Created.After(time.Now()) {
		return nil, errors.New("invalid session creation time")
	}
	b, err := json.Marshal(cached{vpn.Server, vpn.EndpointIPv4, s})
	if err != nil {
		return nil, err
	}
	defer clear(b)
	return usersession.Seal(protectionPurpose(vpn), b)
}
func DecodeRuntime(vpn policy.VPN, raw []byte) (Session, error) {
	b, err := usersession.Open(protectionPurpose(vpn), raw)
	if err != nil {
		return Session{}, err
	}
	defer clear(b)
	var c cached
	if json.Unmarshal(b, &c) != nil || c.Server != vpn.Server || c.Endpoint != vpn.EndpointIPv4 || c.Session.Validate(vpn) != nil {
		return Session{}, errors.New("invalid protected VPN session")
	}
	if !c.Session.ValidAt(time.Now()) {
		return Session{}, errors.New("VPN session expired")
	}
	return c.Session, nil
}
func cacheEncode(vpn policy.VPN, s Session) (any, error)    { return EncodeRuntime(vpn, s) }
func cacheDecode(vpn policy.VPN, b []byte) (Session, error) { return DecodeRuntime(vpn, b) }
