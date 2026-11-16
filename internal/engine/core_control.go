//go:build darwin || windows

package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"netlaunch/internal/companyproxy"
	"netlaunch/internal/lease"
	"netlaunch/internal/policy"
	"slices"
	"strconv"
	"strings"
	"time"
)

func api(run, method, path string, payload, out any) error {
	return apiContext(context.Background(), run, method, path, payload, out)
}
func apiContext(ctx context.Context, run, method, path string, payload, out any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var config struct {
		Secret     string `json:"secret"`
		Controller string `json:"external-controller"`
	}
	if e := readCore(run, &config); e != nil {
		return newCoreFailure("core_configuration_unavailable", e)
	}
	return coreRequest(ctx, config.Controller, config.Secret, method, path, payload, out)
}

// coreRequest owns only bounded local HTTP I/O; run storage stays at the caller.
func coreRequest(ctx context.Context, controller, secret, method, path string, payload, out any) error {
	host, port, err := net.SplitHostPort(controller)
	number, portErr := strconv.Atoi(port)
	if err != nil || host != "127.0.0.1" || portErr != nil || number < 1 || number > 65535 {
		return newCoreFailure("core_binding_invalid", nil)
	}
	var body io.Reader
	if payload != nil {
		b, e := json.Marshal(payload)
		if e != nil {
			return newCoreFailure("core_request_invalid", e)
		}
		body = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, method, "http://"+controller+path, body)
	if e != nil {
		return newCoreFailure("core_request_invalid", e)
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("local control redirects forbidden") }}
	defer client.CloseIdleConnections()
	r, e := client.Do(req)
	if e != nil {
		if ctx.Err() != nil {
			return newCoreFailure("core_request_interrupted", ctx.Err())
		}
		return newCoreFailure("core_unavailable", nil)
	}
	defer r.Body.Close()
	if r.StatusCode != 200 && r.StatusCode != 204 {
		return &coreFailure{code: "core_request_rejected", status: r.StatusCode}
	}
	if out != nil {
		if json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(out) != nil {
			if ctx.Err() != nil {
				return newCoreFailure("core_request_interrupted", ctx.Err())
			}
			return newCoreFailure("core_response_invalid", nil)
		}
	}
	return nil
}
func gate(run string) error {
	return api(run, "PUT", "/proxies/CORP", map[string]string{"name": "REJECT"}, nil)
}
func selectPersonal(run, node string) error {
	return selectPersonalContext(context.Background(), run, node)
}
func selectPersonalContext(ctx context.Context, run, node string) error {
	return selectCoreGroupContext(ctx, run, "PERSONAL", node)
}
func selectCoreGroupContext(ctx context.Context, run, group, node string) error {
	if e := apiContext(ctx, run, "PUT", "/proxies/"+group, map[string]string{"name": node}, nil); e != nil {
		return e
	}
	var current struct {
		Now string `json:"now"`
	}
	if e := apiContext(ctx, run, "GET", "/proxies/"+group, nil, &current); e != nil {
		return e
	}
	if current.Now != node {
		return errors.New("core group selection readback mismatch")
	}
	return nil
}

func probe(ctx context.Context, run string, p policy.Probe, node string, companyDial companyproxy.Dial) (result error) {
	defer func() {
		if result != nil {
			result = describeProbeFailure(p, result)
		}
	}()
	s, e := load(run)
	if e != nil {
		return e
	}
	if e := guard(run, &s); e != nil {
		return e
	}
	u, e := url.Parse(p.URL)
	if e != nil {
		return e
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	host := u.Hostname()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var c net.Conn
	if companyDial != nil {
		number, _ := strconv.Atoi(port)
		c, e = companyDial(ctx, host, number)
	} else {
		d := net.Dialer{Timeout: 4 * time.Second}
		c, e = d.DialContext(ctx, "tcp4", net.JoinHostPort(host, port))
	}
	if e != nil {
		return newProbeFailure("tcp_unavailable", "target TCP not ready")
	}
	defer c.Close()
	deadline := time.Now().Add(4 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	secure := tls.Client(c, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if e = secure.HandshakeContext(ctx); e != nil {
		return tlsProbeFailure(e)
	}
	if companyDial == nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		var data struct {
			Connections []struct {
				Metadata struct {
					SourcePort json.RawMessage `json:"sourcePort"`
					Type       string          `json:"type"`
					Host       string          `json:"host"`
				} `json:"metadata"`
				Chains []string `json:"chains"`
			} `json:"connections"`
		}
		if e = apiContext(ctx, run, "GET", "/connections", nil, &data); e != nil {
			return e
		}
		source := strconv.Itoa(c.LocalAddr().(*net.TCPAddr).Port)
		expected := map[string]string{"company": "CORP", "personal": "PERSONAL", "direct": "PHYSICAL"}[p.Channel]
		found := false
		for _, row := range data.Connections {
			if strings.Trim(string(row.Metadata.SourcePort), "\"") == source && row.Metadata.Type == "Tun" {
				for _, chain := range row.Chains {
					if chain == expected {
						found = p.Channel != "personal" || slices.Contains(row.Chains, node)
					}
				}
			}
		}
		if !found {
			return newProbeFailure("unexpected_system_path", "system probe did not use the expected TUN channel")
		}
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if _, e = fmt.Fprintf(secure, "HEAD %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, u.Host); e != nil {
		return newProbeFailure("http_write_failed", "HTTPS probe write failed")
	}
	response, e := http.ReadResponse(bufio.NewReader(io.LimitReader(secure, 32<<10)), &http.Request{Method: "HEAD"})
	if e != nil {
		return newProbeFailure("http_response_missing", "HTTPS probe response missing")
	}
	response.Body.Close()
	return checkProbeStatus(p, response.StatusCode)
}

type companyProbeSchedule struct {
	*probeSchedule
	session *lease.Session
	open    bool
}

func newCompanyProbeSchedule() *companyProbeSchedule {
	return &companyProbeSchedule{probeSchedule: newProbeSchedule()}
}

func (checks *companyProbeSchedule) close(run string) error {
	if !checks.open {
		return nil
	}
	if err := update(run, func(s *State) error {
		work, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := selectCoreGroupContext(work, run, "CORP", "REJECT"); err != nil {
			return err
		}
		delete(s.Channels, "company")
		return nil
	}); err != nil {
		return &terminalReadinessError{err}
	}
	checks.open = false
	return nil
}

// Step the company-bound ingress independently of system-TUN checks. Pending
// evidence keeps CORP closed and lets startup or the normal loop advance.
func openCompany(ctx context.Context, run string, company *companyRuntime, checks *companyProbeSchedule) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := company.ready(); err != nil {
		checks.reset()
		if closeErr := checks.close(run); closeErr != nil {
			return false, closeErr
		}
		return false, err
	}
	s, e := load(run)
	if e != nil {
		return false, e
	}
	if e = guard(run, &s); e != nil {
		return false, e
	}
	session, generation := company.current()
	if session == nil || generation != s.VPN.Generation {
		checks.reset()
		if err := checks.close(run); err != nil {
			return false, err
		}
		return false, errProbeScopeChanged
	}
	if session != checks.session {
		checks.reset()
		checks.session = session
	}
	scope := scopeForProbes(s, "")
	probes := []policy.Probe{}
	for _, p := range s.Manifest.Config.Probes {
		if p.Channel == "company" {
			probes = append(probes, p)
		}
	}
	checks.bind(scope, probes)
	prior, _ := checks.aggregate("company", "company_bound", time.Now())
	if prior.State != "ready" {
		if e := checks.close(run); e != nil {
			return false, e
		}
	}
	stepped := checks.due(time.Now())
	if e := checks.advance(ctx, func(work context.Context, p policy.Probe) error { return probe(work, run, p, "", company.dial) }); e != nil {
		return false, e
	}
	status, failure := checks.aggregate("company", "company_bound", time.Now())
	if status.State != "ready" {
		if e := checks.close(run); e != nil {
			return false, e
		}
		if !checks.due(time.Now().Add(2 * time.Second)) {
			checks.next = time.Now().Add(2 * time.Second)
		}
		if failure != nil {
			return false, failure
		}
		return false, errors.New("company probe evidence incomplete")
	}
	if checks.open && !stepped && s.Phase != "company_unavailable" {
		return false, nil
	}
	opened := !checks.open || s.Phase == "company_unavailable"
	e = update(run, func(s *State) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e := guard(run, s); e != nil {
			return e
		}
		current, currentGeneration := company.current()
		if scopeForProbes(*s, "") != scope || current != session || currentGeneration != generation || !validVPN(*s) || company.ready() != nil {
			return errors.New("VPN changed during readiness probe")
		}
		if h, _ := checks.aggregate("company", "company_bound", time.Now()); h.State != "ready" {
			return errors.New("company probe evidence expired before opening")
		}
		for _, a := range s.Leases {
			if time.Now().After(a.ExpiresAt) {
				return errors.New("company lease expired before opening")
			}
		}
		work, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if err := selectCoreGroupContext(work, run, "CORP", "CORP-BOUND"); err != nil {
			return err
		}
		if opened {
			delete(s.Channels, "company")
		}
		if s.Phase == "company_unavailable" {
			s.Phase = "reconnecting"
		}
		return nil
	})
	// A failed or interrupted write may have been delivered. Treat it as open
	// until the independent recovery path or a verified close proves otherwise.
	checks.open = true
	if e != nil {
		if closeErr := checks.close(run); closeErr != nil {
			return false, closeErr
		}
	}
	return opened && e == nil, e
}

func leaseExpired(s State) bool {
	if !s.VPN.Bootstrap {
		return false
	}
	for _, a := range s.Leases {
		if time.Now().After(a.ExpiresAt) {
			return true
		}
	}
	return false
}
