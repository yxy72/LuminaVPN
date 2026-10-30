//go:build darwin

package app

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
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

// The real core resolves a node through a controlled physical-bound resolver
// and attempts TLS to a local fixture. TUN is disabled; no external request is
// made. The fixture aborts TLS before proxy credentials can be transmitted.
func TestNodeHostnameUsesPhysicalDNSAndRetainsTLSIdentity(t *testing.T) {
	root := os.Getenv("NETLAUNCH_TEST_RUNTIME")
	if root == "" {
		t.Skip("set NETLAUNCH_TEST_RUNTIME for bundled core integration")
	}
	if _, e := runtimebundle.Verify(root); e != nil {
		t.Fatal(e)
	}
	const hostname = "proxy-endpoint.netlaunch.invalid"
	resolver, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer resolver.Close()
	queries := make(chan string, 8)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, e := resolver.ReadFrom(buf)
			if e != nil {
				return
			}
			if n < 17 {
				continue
			}
			q := append([]byte(nil), buf[:n]...)
			pos := 12
			labels := []string{}
			for pos < n && q[pos] != 0 {
				size := int(q[pos])
				pos++
				if size > 63 || pos+size >= n {
					pos = n
					break
				}
				labels = append(labels, string(q[pos:pos+size]))
				pos += size
			}
			if pos+5 > n {
				continue
			}
			pos++
			name := strings.Join(labels, ".")
			select {
			case queries <- name:
			default:
			}
			if name != hostname || binary.BigEndian.Uint16(q[pos:pos+2]) != 1 {
				continue
			}
			r := append([]byte(nil), q[:pos+4]...)
			binary.BigEndian.PutUint16(r[2:4], 0x8180)
			binary.BigEndian.PutUint16(r[6:8], 1)
			binary.BigEndian.PutUint16(r[8:10], 0)
			binary.BigEndian.PutUint16(r[10:12], 0)
			r = append(r, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1)
			_, _ = resolver.WriteTo(r, peer)
		}
	}()
	node, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer node.Close()
	hellos := make(chan string, 8)
	go func() {
		for {
			c, e := node.Accept()
			if e != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			s := tls.Server(c, &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
				select {
				case hellos <- h.ServerName:
				default:
				}
				return nil, errors.New("intentional local TLS stop")
			}})
			_ = s.Handshake()
			c.Close()
		}
	}()
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
			if p == old {
				unique = false
			}
		}
		if unique {
			ports = append(ports, p)
		}
	}
	cfg.Ports = policy.Ports{Proxy: ports[0], DNS: ports[1]}
	secret := strings.Repeat("local-node-dns-", 3)
	compiled, e := policy.Compile(cfg, []policy.Node{{"type": "vless", "server": hostname, "port": node.Addr().(*net.TCPAddr).Port, "uuid": "11111111-1111-1111-1111-111111111111", "tls": true}}, policy.Binding{Physical: "lo0", VPN: "utun232", TUN: "utun233", ControllerPort: ports[2]}, secret)
	if e != nil {
		t.Fatal(e)
	}
	dns := compiled["dns"].(map[string]any)
	for _, d := range dns["proxy-server-nameserver"].([]string) {
		if !strings.HasSuffix(d, "#PHYSICAL") {
			t.Fatal("unbound bootstrap DNS")
		}
	}
	dns["proxy-server-nameserver"] = []string{"udp://" + resolver.LocalAddr().String() + "#PHYSICAL"}
	dir := testutil.PrivateTempDir(t)
	configPath := filepath.Join(dir, "core.json")
	if e = securefile.Write(configPath, compiled); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(root, "bin/mihomo"), "-d", dir, "-f", configPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = cmd.Process.Signal(os.Interrupt); _ = cmd.Wait() }()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	request := func(path string) error {
		req, e := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://127.0.0.1:%d%s", ports[2], path), nil)
		if e != nil {
			return e
		}
		req.Header.Set("Authorization", "Bearer "+secret)
		r, e := client.Do(req)
		if e != nil {
			return e
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		return nil
	}
	ready := false
	for i := 0; i < 60; i++ {
		if request("/configs") == nil {
			ready = true
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !ready {
		t.Fatal("core API did not start")
	}
	_ = request("/proxies/P001/delay?url=https%3A%2F%2Fprobe.invalid%2F&timeout=1200")
	select {
	case got := <-queries:
		if got != hostname {
			t.Fatal("unexpected bootstrap query", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("node did not use the configured physical resolver")
	}
	select {
	case got := <-hellos:
		if got != hostname {
			t.Fatal("TLS server identity was not retained", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("node did not dial resolved local endpoint")
	}
}
