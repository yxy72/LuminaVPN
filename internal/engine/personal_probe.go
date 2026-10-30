package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"time"

	"netlaunch/internal/policy"
)

func personalProbeClient(address string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(&url.URL{Scheme: "http", Host: address}),
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 4 * time.Second,
			DisableKeepAlives:   true,
		},
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Verify the selected group through the core's ordinary mixed-port ingress.
// Per-node delay endpoints bypass that ingress and are only ranking samples.
// This does not claim that the system TUN path has passed its separate checks.
func verifyPersonalSelection(ctx context.Context, client *http.Client, probes []policy.Probe) error {
	checked := false
	for _, p := range probes {
		if p.Channel != "personal" {
			continue
		}
		checked = true
		req, e := http.NewRequestWithContext(ctx, http.MethodHead, p.URL, nil)
		if e != nil {
			return errors.New("invalid personal HTTPS probe")
		}
		r, e := client.Do(req)
		if e != nil {
			return describeProbeFailure(p, tlsProbeFailure(e))
		}
		r.Body.Close()
		if r.StatusCode < 200 || r.StatusCode >= 400 {
			return describeProbeFailure(p, errors.New("selected personal node returned an unsuccessful HTTP status"))
		}
	}
	if !checked {
		return errors.New("personal HTTPS probe missing")
	}
	return nil
}
