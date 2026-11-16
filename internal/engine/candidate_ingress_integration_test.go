//go:build darwin || windows

package engine

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/securefile"
	"netlaunch/internal/selector"
	"netlaunch/internal/testutil"
)

func candidateFixtureProxy(t *testing.T, status int, hits *atomic.Int32) (*httptest.Server, *httptest.Server) {
	t.Helper()
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Error("fixture did not receive a HEAD probe")
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(target.Close)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodConnect {
			t.Error("fixture did not receive CONNECT")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		up, err := net.DialTimeout("tcp", target.Listener.Addr().String(), 2*time.Second)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer up.Close()
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(up, conn)
			_ = up.Close()
			close(done)
		}()
		_, _ = io.Copy(conn, up)
		_ = conn.Close()
		<-done
	}))
	t.Cleanup(proxy.Close)
	return proxy, target
}

func TestPinnedCoreIsolatesCandidateIngress(t *testing.T) {
	root := os.Getenv("NETLAUNCH_TEST_RUNTIME")
	if root == "" {
		t.Skip("set NETLAUNCH_TEST_RUNTIME for the pinned core fixture")
	}
	if _, err := runtimebundle.Verify(root); err != nil {
		t.Fatal(err)
	}
	var rejected, healthy, incumbent, company atomic.Int32
	fast, target := candidateFixtureProxy(t, 403, &rejected)
	next, _ := candidateFixtureProxy(t, 204, &healthy)
	previous, _ := candidateFixtureProxy(t, 204, &incumbent)
	corp, _ := candidateFixtureProxy(t, 204, &company)
	host := target.Certificate().DNSNames[0]
	probe := policy.Probe{URL: "https://" + host + "/check", Channel: "personal", Purpose: "service"}
	c := policy.Config{Probes: []policy.Probe{probe}, Company: policy.Channel{Domains: []string{"company.example"}}}
	controller, err := platform.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	mixed, err := platform.FreePort()
	if err != nil || mixed == controller {
		t.Fatalf("fixture mixed port: %d, %v", mixed, err)
	}
	c.Ports.Proxy = mixed
	ingress, err := newCandidateIngress(Manifest{Config: c, Binding: policy.Binding{ControllerPort: controller}})
	if err != nil {
		t.Fatal(err)
	}
	const secret = "loopback-fixture-controller-secret"
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(controller))
	proxy := func(name string, srv *httptest.Server) any {
		return map[string]any{"name": name, "type": "http", "server": "127.0.0.1", "port": srv.Listener.Addr().(*net.TCPAddr).Port}
	}
	config := map[string]any{
		"mode": "rule", "allow-lan": false, "bind-address": "127.0.0.1", "ipv6": false,
		"external-controller": address, "secret": secret, "mixed-port": mixed,
		"geo-auto-update": false, "log-level": "silent",
		"profile": map[string]any{"store-selected": false, "store-fake-ip": false},
		"dns":     map[string]any{"enable": false}, "tun": map[string]any{"enable": false}, "sniffer": map[string]any{"enable": false},
		"proxies": []any{proxy("P001", fast), proxy("P002", next), proxy("P003", previous), proxy("company-fixture", corp)},
		"proxy-groups": []any{
			map[string]any{"name": "PERSONAL", "type": "select", "proxies": []string{"REJECT", "P001", "P002", "P003"}},
			map[string]any{"name": "CORP", "type": "select", "proxies": []string{"company-fixture"}},
		},
		"rules": []string{"DOMAIN," + host + ",PERSONAL", "DOMAIN,company.example,CORP", "MATCH,REJECT"},
	}
	ingress.configure(config, c, []string{"P001", "P002", "P003"})
	dir := testutil.PrivateTempDir(t)
	path := filepath.Join(dir, "core.json")
	if err := securefile.Write(path, config); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	name := "mihomo"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	cmd := exec.CommandContext(ctx, filepath.Join(root, "bin", name), "-d", dir, "-f", path)
	hideVPNFixtureWindow(cmd)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	get := func(ctx context.Context, path string, out any) error {
		return coreRequest(ctx, address, secret, "GET", path, nil, out)
	}
	if err := waitReady(ctx, 4*time.Second, func() error { return nil }, func(c context.Context) error {
		return get(c, "/version", nil)
	}); err != nil {
		t.Fatal(err)
	}
	var active struct {
		TUN struct{ Enable bool } `json:"tun"`
		DNS struct{ Enable bool } `json:"dns"`
	}
	if err := get(ctx, "/configs", &active); err != nil || active.TUN.Enable || active.DNS.Enable {
		t.Fatal("fixture must not enable TUN or DNS", err)
	}
	choose := func(group, value string) {
		t.Helper()
		if err := coreRequest(ctx, address, secret, "PUT", "/proxies/"+group, map[string]string{"name": value}, nil); err != nil {
			t.Fatal(err)
		}
	}
	current := func(group string) string {
		t.Helper()
		var got struct{ Now string }
		if err := get(ctx, "/proxies/"+group, &got); err != nil {
			t.Fatal(err)
		}
		return got.Now
	}
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	probeVia := func(work context.Context, port int, user, password, listener, group, node string, target policy.Probe) error {
		return probeHTTPS(work, target, func(ctx context.Context, host string, destPort int) (net.Conn, error) {
			return connectProbeIngress(ctx, port, host, destPort, user, password)
		}, func(ctx context.Context, c net.Conn) error {
			return verifyProbeRouteWith(ctx, c, "HTTPS", listener, group, node, get)
		}, roots)
	}
	choose("PERSONAL", "P003")
	selection := selector.New([]string{"P001", "P002", "P003"})
	selection.Options.Confirmations, selection.Options.MinHold = 1, 0
	now := time.Now()
	selection.Commit("P003", now.Add(-time.Second))
	durations := map[string]int{"P001": 10, "P002": 100, "P003": 1000}
	first, _ := selection.DecideSamples(now, durations)
	if first != "P001" {
		t.Fatalf("first candidate = %q", first)
	}
	choose(candidateGroup, first)
	for _, auth := range [][2]string{{"", ""}, {candidateUser, "wrong"}} {
		if err := probeVia(ctx, ingress.port, auth[0], auth[1], candidateListener, candidateGroup, "P001", probe); probeReason(err) != "core_ingress_authentication_failed" {
			t.Fatalf("unauthenticated probe result: %v", err)
		}
	}
	for _, blocked := range []string{"company.example", "unexpected.example"} {
		p := probe
		p.URL = "https://" + blocked + "/check"
		if err := probeVia(ctx, ingress.port, candidateUser, ingress.password, candidateListener, candidateGroup, "P001", p); err == nil {
			t.Fatal("candidate reached an unrelated destination")
		}
	}
	if rejected.Load()+healthy.Load()+incumbent.Load()+company.Load() != 0 {
		t.Fatal("a rejected candidate request reached an upstream")
	}
	refused := probeVia(ctx, ingress.port, candidateUser, ingress.password, candidateListener, candidateGroup, first, probe)
	if probeReason(refused) != "http_status_rejected" || nodeProbeFailure(refused) {
		t.Fatalf("service refusal lost its actual outcome: %v", refused)
	}
	notePersonalProbeFailure(selection, first, refused)
	second, _ := selection.DecideSamples(time.Now(), durations)
	if second != "P002" {
		t.Fatalf("403 on fastest node starved the working alternative: %q", second)
	}
	choose(candidateGroup, second)
	var targets []policy.Probe
	for i := 0; i < 5; i++ {
		target := probe
		target.URL += "/" + strconv.Itoa(i)
		targets = append(targets, target)
	}
	schedule := newProbeSchedule()
	schedule.bind(probeScope{node: second}, targets)
	check := func(work context.Context, target policy.Probe) error {
		return probeVia(work, ingress.port, candidateUser, ingress.password, candidateListener, candidateGroup, second, target)
	}
	if err := schedule.advance(ctx, check); err != nil {
		t.Fatal(err)
	}
	if status, _ := schedule.aggregate("personal", candidateListener, time.Now()); status.State == "ready" || current("PERSONAL") != "P003" {
		t.Fatal("a partial candidate slice affected the live route")
	}
	if err := schedule.advance(ctx, check); err != nil {
		t.Fatal(err)
	}
	if status, failure := schedule.aggregate("personal", candidateListener, time.Now()); status.State != "ready" {
		t.Fatal("second isolated candidate did not verify all five targets", status, failure)
	}
	if current("PERSONAL") != "P003" || current("CORP") != "company-fixture" {
		t.Fatal("candidate checks changed an active group")
	}
	if err := probeVia(ctx, mixed, "", "", "DEFAULT-MIXED", "PERSONAL", "P003", probe); err != nil {
		t.Fatal("live incumbent did not retain its mixed route", err)
	}
	choose(candidateGroup, selector.Reject)
	if rejected.Load() != 1 || healthy.Load() != 5 || incumbent.Load() != 1 || company.Load() != 0 {
		t.Fatal("tests escaped their expected verification paths")
	}
}
