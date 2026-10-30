package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"netlaunch/internal/policy"
	"strings"
	"testing"
)

func TestProbeFailureNamesTargetWithoutURLSecrets(t *testing.T) {
	p := policy.Probe{Channel: "company", URL: "https://user:secret@service.example/private-path?token=secret"}
	err := describeProbeFailure(p, tlsProbeFailure(context.DeadlineExceeded))
	if !strings.Contains(err.Error(), "company HTTPS probe service.example") || !strings.Contains(err.Error(), "timed out") {
		t.Fatal(err)
	}
	for _, private := range []string{"secret", "private-path", "user:", "token="} {
		if strings.Contains(err.Error(), private) {
			t.Fatal("URL secret exposed")
		}
	}
	if got := tlsProbeFailure(&tls.CertificateVerificationError{Err: errors.New("private peer text")}).Error(); got != "target TLS certificate verification failed" {
		t.Fatal(got)
	}
	if strings.Contains(tlsProbeFailure(errors.New("private peer text")).Error(), "private") {
		t.Fatal("raw peer error exposed")
	}
}
