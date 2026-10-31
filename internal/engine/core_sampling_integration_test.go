//go:build darwin || windows

package engine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/securefile"
	"netlaunch/internal/selector"
	"netlaunch/internal/testutil"
)

// The fixed runtime uses loopback HTTP only; no TUN, DNS or company endpoint.
// It verifies the actual delay/extra contract used by both native coordinators.
func TestPinnedCoreSeparatesPathLatencyFromServiceStatus(t *testing.T) {
	root := os.Getenv("NETLAUNCH_TEST_RUNTIME")
	if root == "" {
		t.Skip("set NETLAUNCH_TEST_RUNTIME for the pinned core fixture")
	}
	if _, err := runtimebundle.Verify(root); err != nil {
		t.Fatal(err)
	}
	port, err := platform.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	address := "127.0.0.1:" + strconv.Itoa(port)
	const secret = "loopback-fixture-secret"
	dir := testutil.PrivateTempDir(t)
	config := map[string]any{
		"mode": "rule", "log-level": "silent", "allow-lan": false, "ipv6": false,
		"external-controller": address, "secret": secret,
		"dns": map[string]any{"enable": false}, "tun": map[string]any{"enable": false},
		"proxies": []any{map[string]any{"name": "fixture-path", "type": "direct"}},
		"rules":   []string{"MATCH,REJECT"},
	}
	path := filepath.Join(dir, "core.json")
	if err := securefile.Write(path, config); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	program := "mihomo"
	if runtime.GOOS == "windows" {
		program += ".exe"
	}
	cmd := exec.CommandContext(ctx, filepath.Join(root, "bin", program), "-d", dir, "-f", path)
	hideVPNFixtureWindow(cmd)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	request := func(ctx context.Context, path string, out any) error {
		return coreRequest(ctx, address, secret, "GET", path, nil, out)
	}
	ready := false
	for i := 0; i < 50; i++ {
		if request(ctx, "/version", nil) == nil {
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("fixture core did not start")
	}
	var active struct {
		TUN struct {
			Enable bool `json:"enable"`
		} `json:"tun"`
	}
	if err := request(ctx, "/configs", &active); err != nil || active.TUN.Enable {
		t.Fatal("fixture TUN was not disabled", err)
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" {
			t.Error("unexpected method", r.Method)
		}
		time.Sleep(15 * time.Millisecond) // the core treats sub-millisecond zero as failure
		w.WriteHeader(503)
	}))
	defer target.Close()
	for _, expected := range []string{"200-399", "200-599"} {
		started := time.Now()
		var delay struct {
			Delay *int `json:"delay"`
		}
		q := url.Values{"url": {target.URL}, "timeout": {"3000"}, "expected": {expected}}
		if err := request(ctx, "/proxies/fixture-path/delay?"+q.Encode(), &delay); err != nil {
			t.Fatal("delay endpoint contract changed", err)
		}
		var details struct {
			Extra map[string]selector.ProbeState `json:"extra"`
		}
		if err := request(ctx, "/proxies/fixture-path", &details); err != nil {
			t.Fatal(err)
		}
		value, known := selector.ObservedDelay(started, time.Now(), delay.Delay, details.Extra[target.URL])
		if !known || (value >= 0) != (expected == "200-599") {
			t.Fatal("pinned core status/history contract changed", expected, value, known)
		}
	}
	values := measurePersonalWith(ctx, []string{"fixture-path"}, []string{target.URL}, request)
	if delay, ok := values["fixture-path"]; !ok || delay < 0 {
		t.Fatal("HTTP service failure misclassified as unreachable node", values)
	}
	badAuth := func(ctx context.Context, path string, out any) error {
		return coreRequest(ctx, address, "wrong-fixture-secret", "GET", path, nil, out)
	}
	if values := measurePersonalWith(ctx, []string{"fixture-path"}, []string{target.URL}, badAuth); len(values) != 0 {
		t.Fatal("controller authentication failure blamed node", values)
	}
	target.Close()
	values = measurePersonalWith(ctx, []string{"fixture-path"}, []string{target.URL}, request)
	if value, ok := values["fixture-path"]; !ok || value >= 0 {
		t.Fatal("closed target was not a measured path failure", values)
	}
}
