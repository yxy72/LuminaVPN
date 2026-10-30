//go:build darwin

package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/securefile"
	"netlaunch/internal/testutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Opt-in integration uses loopback listeners only. TUN remains false throughout.
func TestBundledCoreWithoutTUN(t *testing.T) {
	root := os.Getenv("NETLAUNCH_TEST_RUNTIME")
	if root == "" {
		t.Skip("set NETLAUNCH_TEST_RUNTIME for the bundled-core integration")
	}
	if _, e := runtimebundle.Verify(root); e != nil {
		t.Fatal(e)
	}
	cfg, e := policy.Decode([]byte(Example))
	if e != nil {
		t.Fatal(e)
	}
	ports := []int{}
	for len(ports) < 3 {
		p, e := platform.FreePort()
		if e != nil {
			t.Fatal(e)
		}
		unique := true
		for _, old := range ports {
			if old == p {
				unique = false
			}
		}
		if unique {
			ports = append(ports, p)
		}
	}
	cfg.Ports = policy.Ports{Proxy: ports[0], DNS: ports[1]}
	cfg.PersonalRules = []policy.Rule{{Type: "DOMAIN-SUFFIX", Value: "example.org", Target: "personal"}, {Type: "DOMAIN", Value: "denied.example.net", Target: "reject"}, {Type: "IP-CIDR", Value: "203.0.112.0/24", Target: "direct"}}
	secret := strings.Repeat("local-integration-", 3)
	compiled, e := policy.Compile(cfg, []policy.Node{{"type": "vless", "server": "203.0.113.7", "port": 443, "uuid": "11111111-1111-1111-1111-111111111111", "tls": true}}, policy.Binding{Physical: "lo0", VPN: "utun232", TUN: "utun233", ControllerPort: ports[2]}, secret)
	if e != nil {
		t.Fatal(e)
	}
	dir := testutil.PrivateTempDir(t)
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "core.json")
	if e = securefile.Write(path, compiled); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	core := filepath.Join(root, "bin/mihomo")
	if b, e := exec.CommandContext(ctx, core, "-t", "-d", dir, "-f", path).CombinedOutput(); e != nil {
		t.Fatalf("bundled core rejected generated config: %s", b)
	}
	cmd := exec.CommandContext(ctx, core, "-d", dir, "-f", path)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Signal(os.Interrupt); cmd.Wait() }()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
	defer client.CloseIdleConnections()
	address := compiled["external-controller"].(string)
	get := func(route string, token bool) (int, map[string]any, error) {
		req, _ := http.NewRequest("GET", "http://"+address+route, nil)
		if token {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		r, e := client.Do(req)
		if e != nil {
			return 0, nil, e
		}
		defer r.Body.Close()
		var body map[string]any
		json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
		return r.StatusCode, body, nil
	}
	ready := false
	for i := 0; i < 40; i++ {
		if status, _, e := get("/version", true); e == nil && status == 200 {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("core API not ready")
	}
	if status, _, e := get("/version", false); e != nil || status != 401 {
		t.Fatal("controller accepted unauthenticated request", status, e)
	}
	_, actual, e := get("/configs", true)
	if e != nil {
		t.Fatal(e)
	}
	if actual["tun"].(map[string]any)["enable"] != false {
		t.Fatal("integration enabled TUN")
	}
	for _, group := range []string{"CORP", "PERSONAL"} {
		_, body, e := get("/proxies/"+group, true)
		if e != nil || body["now"] != "REJECT" {
			t.Fatal("channel initially open", body, e)
		}
	}
	_, rules, e := get("/rules", true)
	if e != nil {
		t.Fatal(e)
	}
	rows := rules["rules"].([]any)
	last := rows[len(rows)-1].(map[string]any)
	if last["proxy"] != "PHYSICAL" {
		t.Fatal("core changed default exit", last)
	}
}
