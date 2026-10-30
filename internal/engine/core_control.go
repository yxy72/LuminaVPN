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
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"strconv"
	"strings"
	"time"
)

func api(run, method, path string, payload, out any) error {
	var config struct {
		Secret     string `json:"secret"`
		Controller string `json:"external-controller"`
	}
	if e := readCore(run, &config); e != nil {
		return e
	}
	if !strings.HasPrefix(config.Controller, "127.0.0.1:") {
		return errors.New("invalid local control binding")
	}
	var body io.Reader
	if payload != nil {
		b, e := json.Marshal(payload)
		if e != nil {
			return e
		}
		body = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, method, "http://"+config.Controller+path, body)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+config.Secret)
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("local control redirects forbidden") }}
	defer client.CloseIdleConnections()
	r, e := client.Do(req)
	if e != nil {
		return errors.New("local core unavailable")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 && r.StatusCode != 204 {
		return errors.New("local core rejected request")
	}
	if out != nil {
		if json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(out) != nil {
			return errors.New("invalid local core response")
		}
	}
	return nil
}
func gate(run string) error {
	return api(run, "PUT", "/proxies/CORP", map[string]string{"name": "REJECT"}, nil)
}
func selectPersonal(run, node string) error {
	if e := api(run, "PUT", "/proxies/PERSONAL", map[string]string{"name": node}, nil); e != nil {
		return e
	}
	var current struct {
		Now string `json:"now"`
	}
	if e := api(run, "GET", "/proxies/PERSONAL", nil, &current); e != nil {
		return e
	}
	if current.Now != node {
		return errors.New("personal selection readback mismatch")
	}
	return nil
}

func probe(run string, p policy.Probe, bound bool, companyDial ...companyproxy.Dial) (result error) {
	defer func() {
		if result != nil {
			result = describeProbeFailure(p, result)
		}
	}()
	s, e := load(run)
	if e != nil {
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var c net.Conn
	if bound && len(companyDial) > 0 {
		number, _ := strconv.Atoi(port)
		c, e = companyDial[0](ctx, host, number)
	} else if bound {
		ip := ""
		for _, l := range s.Leases {
			if l.Domain == host && time.Now().Before(l.ExpiresAt) {
				ip = l.IP
				break
			}
		}
		if ip == "" {
			return errors.New("probe has no current company lease")
		}
		c, e = platform.BoundDial(s.VPN.Interface)(ctx, "tcp4", net.JoinHostPort(ip, port))
	} else {
		d := net.Dialer{Timeout: 4 * time.Second}
		c, e = d.DialContext(ctx, "tcp4", net.JoinHostPort(host, port))
	}
	if e != nil {
		return errors.New("target TCP not ready")
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	secure := tls.Client(c, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if e = secure.HandshakeContext(ctx); e != nil {
		return tlsProbeFailure(e)
	}
	if !bound {
		time.Sleep(100 * time.Millisecond)
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
		if e = api(run, "GET", "/connections", nil, &data); e != nil {
			return e
		}
		source := strconv.Itoa(c.LocalAddr().(*net.TCPAddr).Port)
		expected := map[string]string{"company": "CORP", "personal": "PERSONAL", "direct": "PHYSICAL"}[p.Channel]
		found := false
		for _, row := range data.Connections {
			if strings.Trim(string(row.Metadata.SourcePort), "\"") == source && row.Metadata.Type == "Tun" {
				for _, chain := range row.Chains {
					if chain == expected {
						found = true
					}
				}
			}
		}
		if !found {
			return errors.New("system probe did not use the expected TUN channel")
		}
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if _, e = fmt.Fprintf(secure, "HEAD %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, u.Host); e != nil {
		return errors.New("HTTPS probe write failed")
	}
	response, e := http.ReadResponse(bufio.NewReader(io.LimitReader(secure, 32<<10)), &http.Request{Method: "HEAD"})
	if e != nil {
		return errors.New("HTTPS probe response missing")
	}
	response.Body.Close()
	return nil
}

func openCompany(run string, company *companyRuntime) error {
	if e := company.ready(); e != nil {
		return e
	}
	s, e := load(run)
	if e != nil {
		return e
	}
	generation := s.VPN.Generation
	for _, p := range s.Manifest.Config.Probes {
		if p.Channel == "company" {
			if e = probe(run, p, true, company.dial); e != nil {
				return e
			}
		}
	}
	return update(run, func(s *State) error {
		if e := guard(run, s); e != nil {
			return e
		}
		if s.VPN.Generation != generation || !validVPN(*s) || company.ready() != nil {
			return errors.New("VPN changed during readiness probe")
		}
		for _, a := range s.Leases {
			if time.Now().After(a.ExpiresAt) {
				return errors.New("company lease expired before opening")
			}
		}
		return api(run, "PUT", "/proxies/CORP", map[string]string{"name": "CORP-BOUND"}, nil)
	})
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
