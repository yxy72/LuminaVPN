//go:build windows

package engine

import (
	"errors"
	"time"
)

// Desktop company terminal failures are isolated only after strict cleanup of
// that VPN. Ownership/observation/guard failures still abort the whole runtime.
// Shared legacy and Darwin retry policy is deliberately unchanged.
func desktopVPNFailure(retry *vpnRetry, now time.Time, child Child, reason string, stopCompany func() error) (string, error) {
	err := retry.Failed(now, child, reason)
	if err == nil {
		return "", nil
	}
	var terminal *vpnPolicyFailure
	if !errors.As(err, &terminal) || (terminal.code != "certificate_rejected" && terminal.code != "runtime_load_failed") {
		return "", err
	}
	if err = stopCompany(); err != nil {
		return "", err
	}
	return terminal.code, nil
}

func markDesktopCompanyTerminal(s *State, reason string, now time.Time) {
	if s.Channels == nil {
		s.Channels = map[string]ChannelHealth{}
	}
	s.Channels["company"] = ChannelHealth{ChannelStatus: ChannelStatus{State: "blocked", Reason: reason, NextAction: "review_company_configuration", CheckedAt: now}, Network: s.Manifest.Network}
}
