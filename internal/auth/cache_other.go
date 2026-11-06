//go:build !windows

package auth

import (
	"encoding/json"
	"errors"
	"netlaunch/internal/policy"
)

const removeInvalidCache = false

func EncodeRuntime(vpn policy.VPN, s Session) (any, error) {
	if e := s.Validate(vpn); e != nil {
		return nil, e
	}
	return s, nil
}
func DecodeRuntime(vpn policy.VPN, b []byte) (Session, error) {
	var s Session
	if json.Unmarshal(b, &s) != nil {
		return s, errors.New("invalid VPN session")
	}
	return s, s.Validate(vpn)
}
func cacheEncode(vpn policy.VPN, s Session) (any, error) {
	return cached{vpn.Server, vpn.EndpointIPv4, s}, nil
}
func cacheDecode(vpn policy.VPN, b []byte) (Session, error) {
	var c cached
	if json.Unmarshal(b, &c) != nil || c.Server != vpn.Server || c.Endpoint != vpn.EndpointIPv4 || c.Session.Validate(vpn) != nil {
		return Session{}, errors.New("invalid VPN cache")
	}
	return c.Session, nil
}
