package engine

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netlaunch/internal/securefile"
	"netlaunch/internal/testutil"
)

func TestDarwinPinnedCoreRefreshesRuleProviderWithoutDisconnecting(t *testing.T) {
	root := os.Getenv("NETLAUNCH_TEST_RUNTIME")
	if root == "" {
		t.Skip("set NETLAUNCH_TEST_RUNTIME for the pinned core fixture")
	}
	if err := requireDarwinReloadCore(root); err != nil {
		t.Fatal(err)
	}
	const host, secret = "whitelist.example", "loopback-rule-provider-fixture"
	original := [4]byte{192, 0, 2, 17}
	updated := [4]byte{203, 0, 113, 42}
	resolver := fakeIPFixturePort(t)
	serveFixtureDNSAnswer(t, resolver, original)
	alternate := fakeIPFixturePort(t)
	serveFixtureDNSAnswer(t, alternate, updated)
	dnsListener := fakeIPFixturePort(t)
	dns := dnsListener.LocalAddr().(*net.UDPAddr)
	_ = dnsListener.Close()

	controller := httptest.NewUnstartedServer(nil)
	controllerAddress := controller.Listener.Addr().String()
	mixed := httptest.NewUnstartedServer(nil)
	mixedAddress := mixed.Listener.Addr().String()
	mixedPort := mixed.Listener.Addr().(*net.TCPAddr).Port
	_ = mixed.Listener.Close()
	_ = controller.Listener.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "fixture")
	}))
	defer target.Close()
	targetAddress := target.Listener.Addr().String()
	dir := testutil.PrivateTempDir(t)
	provider := filepath.Join(dir, "whitelist.txt")
	writeRules := func(rules []string) {
		t.Helper()
		if err := os.WriteFile(provider+".next", []byte(strings.Join(rules, "\n")+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(provider+".next", provider); err != nil {
			t.Fatal(err)
		}
	}
	writeRules([]string{})

	file := filepath.Join(dir, "core.json")
	config := map[string]any{
		"mode": "rule", "log-level": "silent", "ipv6": false, "allow-lan": false,
		"mixed-port": mixedPort, "bind-address": "127.0.0.1", "external-controller": controllerAddress, "secret": secret,
		"tun": map[string]any{"enable": false},
		"rule-providers": map[string]any{"whitelist": map[string]any{
			"type": "file", "behavior": "classical", "format": "text", "path": "./whitelist.txt",
		}},
		"rules": []string{"RULE-SET,whitelist,REJECT,no-resolve", "MATCH,DIRECT"},
		"dns": map[string]any{
			"enable": true, "listen": dns.String(), "ipv6": false, "enhanced-mode": "normal",
			"nameserver": []string{"udp://" + resolver.LocalAddr().String()},
			"nameserver-policy": map[string][]string{
				"rule-set:whitelist": {"udp://" + alternate.LocalAddr().String()},
			},
		},
	}
	if err := securefile.Write(file, config); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(root, "bin", "mihomo"), "-d", dir, "-f", file)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	api := func(c context.Context, method, path string) error {
		return coreRequest(c, controllerAddress, secret, method, path, nil, nil)
	}
	if err := waitReady(ctx, 4*time.Second, func() error { return nil }, func(c context.Context) error {
		return api(c, "GET", "/version")
	}); err != nil {
		t.Fatal(err)
	}

	lookup := func() netip.Addr {
		t.Helper()
		conn, err := net.DialUDP("udp4", nil, dns)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		question := fakeIPQuestion(host)
		if _, err := conn.Write(question); err != nil {
			t.Fatal(err)
		}
		var buffer [512]byte
		n, err := conn.Read(buffer[:])
		if err != nil || n < len(question)+16 || binary.BigEndian.Uint16(buffer[6:8]) != 1 {
			t.Fatalf("fixture DNS response: %d bytes, %v", n, err)
		}
		return netip.AddrFrom4([4]byte(buffer[n-4 : n]))
	}
	open := func() (net.Conn, *bufio.Reader) {
		t.Helper()
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", mixedAddress)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddress, targetAddress); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(conn)
		response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("fixture CONNECT did not start: %v", err)
		}
		return conn, reader
	}
	get := func(conn net.Conn, reader *bufio.Reader) (string, error) {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddress); err != nil {
			return "", err
		}
		response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
		if err != nil {
			return "", err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 64))
		return string(body), err
	}

	existing, reader := open()
	if got, err := get(existing, reader); err != nil || got != "fixture" {
		t.Fatalf("existing fixture stream did not start: %q, %v", got, err)
	}
	if got := lookup(); got != netip.AddrFrom4(original) {
		t.Fatal("original DNS policy did not match", got)
	}
	writeRules([]string{"DOMAIN," + host, "IP-CIDR,127.0.0.1/32,no-resolve"})
	if err := api(ctx, "PUT", "/providers/rules/whitelist"); err != nil {
		t.Fatal(err)
	}
	next, nextReader := open()
	if got, err := get(next, nextReader); err == nil {
		t.Fatalf("new stream ignored updated rule: %q", got)
	}
	if got, err := get(existing, reader); err != nil || got != "fixture" {
		t.Fatalf("provider refresh disconnected an existing stream: %q, %v", got, err)
	}
	if err := api(ctx, "POST", "/cache/dns/flush"); err != nil {
		t.Fatal(err)
	}
	if got := lookup(); got != netip.AddrFrom4(updated) {
		t.Fatal("updated DNS policy did not match the same provider", got)
	}
}
