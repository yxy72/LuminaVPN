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

type probeFailure struct{ code, message string }

func (e *probeFailure) Error() string            { return e.message }
func newProbeFailure(code, message string) error { return &probeFailure{code, message} }
func probeReason(err error) string {
	var core *coreFailure
	if errors.As(err, &core) {
		return core.code
	}
	var failure *probeFailure
	if errors.As(err, &failure) {
		return failure.code
	}
	return "path_probe_failed"
}

func checkProbeStatus(p policy.Probe, code int) error {
	if code < 200 || code > 599 {
		return newProbeFailure("http_response_missing", "HTTPS probe did not return a final HTTP response")
	}
	if p.AcceptsStatus(code) {
		return nil
	}
	return newProbeFailure("http_status_rejected", "HTTPS response did not match the configured expectation")
}

func requestProbeFailure(err error) error {
	var operation *net.OpError
	if errors.As(err, &operation) && operation.Op == "dial" {
		if address, ok := operation.Addr.(*net.TCPAddr); ok && address.IP.IsLoopback() {
			return newCoreFailure("core_ingress_unavailable", nil)
		}
		return newProbeFailure("tcp_unavailable", "target TCP not ready")
	}
	return tlsProbeFailure(err)
}

func nodeProbeFailure(err error) bool {
	switch probeReason(err) {
	case "tcp_unavailable", "tls_certificate_invalid", "tls_timeout", "tls_failed", "http_write_failed", "http_response_missing":
		return true
	}
	return false
}

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
		return newProbeFailure("tls_certificate_invalid", "target TLS certificate verification failed")
	}
	var network net.Error
	if errors.Is(e, context.DeadlineExceeded) || errors.As(e, &network) && network.Timeout() {
		return newProbeFailure("tls_timeout", "target TLS handshake timed out")
	}
	return newProbeFailure("tls_failed", "target TLS handshake failed")
}
