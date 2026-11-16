//go:build darwin || windows

package engine

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/selector"
)

const (
	candidateGroup    = "LUMINA-VERIFY"
	candidateListener = "lumina-candidate"
	candidateSubrule  = "lumina-candidate-only"
	candidateUser     = "lumina-probe"
)

type candidateIngress struct {
	port     int
	password string
}

func newCandidateIngress(m Manifest) (candidateIngress, error) {
	for i := 0; i < 8; i++ {
		port, err := platform.FreePort()
		if err != nil {
			return candidateIngress{}, err
		}
		if port == m.Binding.ControllerPort || port == m.Config.Ports.Proxy || port == m.Config.Ports.DNS {
			continue
		}
		var password [24]byte
		if _, err := rand.Read(password[:]); err != nil {
			return candidateIngress{}, err
		}
		return candidateIngress{port, hex.EncodeToString(password[:])}, nil
	}
	return candidateIngress{}, errors.New("no local candidate probe port is available")
}

func (l candidateIngress) configure(config map[string]any, c policy.Config, names []string) {
	var rules []string
	seen := map[string]bool{}
	for _, p := range c.Probes {
		u, err := url.Parse(p.URL)
		if p.Channel != "personal" || err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if !policy.ValidDomain(host) || c.IsCompany(host) || seen[host] {
			continue
		}
		seen[host] = true
		rules = append(rules, "DOMAIN,"+host+","+candidateGroup)
	}
	config["listeners"] = []any{map[string]any{
		"name": candidateListener, "type": "http", "listen": "127.0.0.1", "port": l.port,
		"users": []map[string]string{{"username": candidateUser, "password": l.password}}, "rule": candidateSubrule,
	}}
	config["skip-auth-prefixes"] = []string{}
	config["sub-rules"] = map[string][]string{candidateSubrule: append(rules, "MATCH,REJECT")}
	// A missing or ignored listener subrule must never reach the main routes.
	config["rules"] = append([]string{"IN-NAME," + candidateListener + ",REJECT"}, config["rules"].([]string)...)
	config["proxy-groups"] = append(config["proxy-groups"].([]any), map[string]any{
		"name": candidateGroup, "type": "select", "proxies": append([]string{selector.Reject}, names...),
	})
}

func candidateNames(nodes []policy.Node) []string {
	names := make([]string, 0, len(nodes))
	for _, node := range nodes {
		names = append(names, node["name"].(string))
	}
	return names
}

func (l candidateIngress) probe(ctx context.Context, run string, p policy.Probe, node string) error {
	return probeHTTPIngress(ctx, run, p, l.port, candidateUser, l.password, candidateListener, candidateGroup, node)
}

func probeHTTPIngress(ctx context.Context, run string, p policy.Probe, port int, user, password, listener, group, node string) error {
	return probeHTTPS(ctx, p, func(ctx context.Context, host string, targetPort int) (net.Conn, error) {
		return connectProbeIngress(ctx, port, host, targetPort, user, password)
	}, func(ctx context.Context, c net.Conn) error {
		return verifyProbeRoute(ctx, run, c, "HTTPS", listener, group, node)
	}, nil)
}

func connectProbeIngress(ctx context.Context, port int, host string, targetPort int, user, password string) (net.Conn, error) {
	dial := net.Dialer{Timeout: 4 * time.Second}
	conn, err := dial.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, newCoreFailure("core_ingress_unavailable", err)
	}
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	open := conn
	stop := context.AfterFunc(ctx, func() { _ = open.Close() })
	defer stop()
	target := net.JoinHostPort(host, strconv.Itoa(targetPort))
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "http://"+target, nil)
	if err != nil {
		return nil, newCoreFailure("core_request_invalid", err)
	}
	if user != "" {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+password)))
	}
	if err := req.Write(conn); err != nil {
		return nil, newCoreFailure("core_ingress_unavailable", err)
	}
	reader := bufio.NewReader(io.LimitReader(conn, 8<<10))
	// Parse headers only. A successful CONNECT transitions to raw TLS, so
	// interpreting the tunnel as an HTTP response body can consume its bytes.
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodHead})
	if err != nil {
		return nil, newCoreFailure("core_ingress_unavailable", err)
	}
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusProxyAuthRequired || response.StatusCode == http.StatusForbidden {
			return nil, newCoreFailure("core_ingress_authentication_failed", nil)
		}
		return nil, newProbeFailure("tcp_unavailable", "core could not connect to the probe target")
	}
	// HTTPS requires the client to start the TLS handshake after CONNECT.
	if reader.Buffered() != 0 {
		return nil, newCoreFailure("core_ingress_response_invalid", nil)
	}
	conn = nil
	return open, nil
}
