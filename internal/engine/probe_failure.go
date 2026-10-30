package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"

	"netlaunch/internal/policy"
)

func describeProbeFailure(p policy.Probe, e error) error {
	host := "invalid-target"
	if u, err := url.Parse(p.URL); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	return fmt.Errorf("%s HTTPS probe %s: %w", p.Channel, host, e)
}

func tlsProbeFailure(e error) error {
	var certificate *tls.CertificateVerificationError
	if errors.As(e, &certificate) {
		return errors.New("target TLS certificate verification failed")
	}
	var network net.Error
	if errors.Is(e, context.DeadlineExceeded) || errors.As(e, &network) && network.Timeout() {
		return errors.New("target TLS handshake timed out")
	}
	return errors.New("target TLS handshake failed")
}
