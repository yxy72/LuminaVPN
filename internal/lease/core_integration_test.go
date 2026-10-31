package lease

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"netlaunch/internal/companyproxy"
	"netlaunch/internal/dnswire"
	"netlaunch/internal/selector"
)

// This fixture exercises the real authenticated company ingress with a lease
// authority. All listeners and real connections are loopback-only; approved
// fixture addresses are mapped to net.Pipe instead of a native VPN adapter.
// It never enables TUN or edits the host's DNS, routes or existing proxy.
func TestCorePreservesDomainAcrossLeaseRotation(t *testing.T) {
	t.Run("fake_ip", func(t *testing.T) { coreLeaseCase(t, false, false, false, false) })
	t.Run("hosts_mapping_rejected", func(t *testing.T) { coreLeaseCase(t, true, false, false, false) })
	t.Run("real_time_expiry", func(t *testing.T) { coreLeaseCase(t, false, true, false, false) })
	t.Run("real_time_cname_expiry", func(t *testing.T) { coreLeaseCase(t, false, true, true, false) })
	t.Run("request_waits_for_renewal", func(t *testing.T) { coreLeaseCase(t, false, true, true, true) })
}

func coreLeaseCase(t *testing.T, hostsMapping, realTime, wireDNS, renewing bool) {
	const host = "service.test"
	core := os.Getenv("NETLAUNCH_TEST_CORE")
	if core == "" {
		t.Skip("set NETLAUNCH_TEST_CORE to a local Mihomo executable")
	}
	_, s, clock := setup(t, host)
	if realTime {
		a, e := New([]string{host}, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(a.Revoke)
		s = a.Begin(context.Background())
	}
	grant := func(ip string) dnswire.Answer {
		if wireDNS {
			return cnameDNSGrant(t, host, ip)
		}
		if realTime {
			return answer(&testClock{t: time.Now()}, host, ip, 2)
		}
		return answer(clock, host, ip, 2)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var dials, requests []string
	credentials := companyproxy.Credentials{Username: "company", Password: strings.Repeat("loopback-test-", 4)}
	server, err := companyproxy.New(credentials, func(ctx context.Context, target string, port int) (net.Conn, error) {
		mu.Lock()
		if net.ParseIP(target) != nil {
			requests = append(requests, "not-domain-connect")
		} else {
			requests = append(requests, target)
		}
		mu.Unlock()
		dial := s.DialContext
		if renewing {
			dial = s.DialRenewingContext
		}
		return dial(ctx, target, port, func(_ context.Context, network, address string) (net.Conn, error) {
			mu.Lock()
			dials = append(dials, address)
			mu.Unlock()
			l, r := net.Pipe()
			go func() {
				defer r.Close()
				r.SetDeadline(time.Now().Add(3 * time.Second))
				if _, e := http.ReadRequest(bufio.NewReader(r)); e != nil {
					return
				}
				time.Sleep(5 * time.Millisecond)
				fmt.Fprintf(r, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(address), address)
			}()
			return l, nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, stopServer := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(serverCtx, listener) }()
	defer func() { stopServer(); <-serverDone }()
	proxy, err := companyproxy.Proxy(listener.Addr().String(), credentials)
	if err != nil {
		t.Fatal(err)
	}
	proxy["name"] = "LEASED"

	port := func() int {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	proxyPort, controllerPort := port(), port()
	for proxyPort == controllerPort {
		controllerPort = port()
	}
	secret := "loopback-integration-only-control-token"
	config := map[string]any{
		"mixed-port": proxyPort, "bind-address": "127.0.0.1", "allow-lan": false, "mode": "rule", "log-level": "debug", "ipv6": false,
		"external-controller": net.JoinHostPort("127.0.0.1", strconv.Itoa(controllerPort)), "secret": secret,
		"tun": map[string]any{"enable": false}, "geo-auto-update": false,
		"profile": map[string]any{"store-selected": false, "store-fake-ip": false},
		"dns":     map[string]any{"enable": true, "enhanced-mode": "fake-ip", "fake-ip-range": "198.19.0.1/16", "use-hosts": false, "use-system-hosts": false, "nameserver": []string{"tcp://" + staleDNS(t)}, "fallback": []string{}},
		"proxies": []any{proxy},
		"rules":   []string{"DOMAIN," + host + ",LEASED", "MATCH,REJECT"},
	}
	if hostsMapping {
		config["hosts"] = map[string]string{host: "10.1.2.3"}
		config["dns"].(map[string]any)["use-hosts"] = true
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "core.json")
	body, _ := json.Marshal(config)
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, core, "-d", dir, "-f", path)
	var coreLog bytes.Buffer
	cmd.Stdout = &coreLog
	cmd.Stderr = &coreLog
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(coreLog.String())
		}
	})
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	control := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 500 * time.Millisecond}
	defer control.CloseIdleConnections()
	ready := false
	for i := 0; i < 40; i++ {
		req, _ := http.NewRequest("GET", "http://"+config["external-controller"].(string)+"/configs", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		res, e := control.Do(req)
		if e == nil {
			var actual struct {
				TUN struct {
					Enable bool `json:"enable"`
				} `json:"tun"`
			}
			e = json.NewDecoder(res.Body).Decode(&actual)
			res.Body.Close()
			if e == nil && res.StatusCode == 200 {
				if actual.TUN.Enable {
					t.Fatal("fixture enabled TUN")
				}
				// The controller opens before the DNS and mixed listeners finish
				// initialization. A configs response alone is not core readiness.
				conn, dialErr := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)), 100*time.Millisecond)
				if dialErr == nil {
					conn.Close()
					ready = true
					break
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("fixture core not ready")
	}
	// Prime the core's real-address DNS cache with A, then retain it throughout
	// rotation. The authority will move to B independently of that stale cache.
	cachedA := func() {
		req, _ := http.NewRequest("GET", "http://"+config["external-controller"].(string)+"/dns/query?name="+host+"&type=A", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		res, e := control.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		b, e := io.ReadAll(io.LimitReader(res.Body, 4096))
		if e != nil || res.StatusCode != 200 || !strings.Contains(string(b), "10.1.2.3") {
			t.Fatal("core cache did not retain fixture A", string(b), e)
		}
	}
	cachedA()
	proxyURL, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(proxyPort))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}, Timeout: 2 * time.Second}
	defer client.CloseIdleConnections()
	request := func() (string, error) {
		res, e := client.Get("http://" + host + ":8443/")
		if e != nil {
			return "", e
		}
		defer res.Body.Close()
		b, e := io.ReadAll(io.LimitReader(res.Body, 1024))
		if res.StatusCode != 200 {
			return "", fmt.Errorf("proxy status %d", res.StatusCode)
		}
		return string(b), e
	}
	// Start the short lease after core readiness; slow process startup must
	// not consume the TTL before the first positive control can run.
	publish(t, s, grant("10.1.2.3"))
	if hostsMapping {
		if got, e := request(); e == nil {
			t.Fatal("domain-erasing hosts mapping was admitted", got)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(dials) != 0 || len(requests) == 0 {
			t.Fatal("missing hosts rejection", requests, dials)
		}
		for _, r := range requests {
			if r != "not-domain-connect" {
				t.Fatal("unexpected hosts representation", requests)
			}
		}
		return
	}
	if got, e := request(); e != nil || got != "10.1.2.3:8443" {
		mu.Lock()
		t.Log("requests", requests, "dials", dials)
		mu.Unlock()
		t.Fatal("initial lease", got, e)
	}
	if realTime {
		time.Sleep(2 * time.Second)
	} else {
		clock.advance(2 * time.Second)
	}
	if renewing {
		type result struct {
			body string
			err  error
		}
		pending := make(chan result, 1)
		go func() { body, err := request(); pending <- result{body, err} }()
		select {
		case got := <-pending:
			t.Fatal("request did not wait for new grant", got)
		case <-time.After(150 * time.Millisecond):
		}
		mu.Lock()
		count := len(dials)
		mu.Unlock()
		if count != 1 {
			t.Fatal("pending request dialed the expired address")
		}
		publish(t, s, grant("10.1.2.4"))
		got := <-pending
		if got.err != nil || got.body != "10.1.2.4:8443" {
			t.Fatal("pending request did not use refreshed address", got)
		}
	} else {
		if got, e := request(); e == nil {
			t.Fatal("expired lease still dialed", got)
		}
		publish(t, s, grant("10.1.2.4"))
	}
	if got, e := request(); e != nil || got != "10.1.2.4:8443" {
		t.Fatal("first request after rotation used stale core address", got, e)
	}
	probeURL := "http://" + host + ":8443/"
	for _, expected := range []string{"200-399", "204"} {
		started := time.Now()
		q := url.Values{"url": {probeURL}, "timeout": {"1000"}, "expected": {expected}}
		req, _ := http.NewRequest("GET", "http://"+config["external-controller"].(string)+"/proxies/LEASED/delay?"+q.Encode(), nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		response, e := control.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		var delay struct {
			Delay *int `json:"delay"`
		}
		json.NewDecoder(response.Body).Decode(&delay)
		response.Body.Close()
		req, _ = http.NewRequest("GET", "http://"+config["external-controller"].(string)+"/proxies/LEASED", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		response, e = control.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		var details struct {
			Extra map[string]selector.ProbeState `json:"extra"`
		}
		e = json.NewDecoder(response.Body).Decode(&details)
		response.Body.Close()
		if e != nil {
			t.Fatal(e)
		}
		healthy := selector.HealthyDelay(started, time.Now(), delay.Delay, details.Extra[probeURL])
		if (healthy >= 0) != (expected == "200-399") {
			t.Fatal("incorrect HTTP health result", expected, healthy)
		}
	}
	cachedA()
	mu.Lock()
	defer mu.Unlock()
	if len(dials) < 2 || dials[0] != "10.1.2.3:8443" || dials[1] != "10.1.2.4:8443" {
		t.Fatal("unexpected upstream dials", dials)
	}
	for _, name := range requests {
		if name != host {
			t.Fatal("core lost domain", requests)
		}
	}
}

// A local resolver deliberately keeps serving A with a long TTL. It has no
// external upstream, so neither this fixture nor the test core needs the LAN.
func staleDNS(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	stopped := make(chan struct{})
	var workers sync.WaitGroup
	go func() {
		defer close(stopped)
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				for {
					var size [2]byte
					if _, e := io.ReadFull(c, size[:]); e != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(size[:]))
					if len(q) < 12 {
						return
					}
					if _, e := io.ReadFull(c, q); e != nil {
						return
					}
					qtype := binary.BigEndian.Uint16(q[len(q)-4:])
					binary.BigEndian.PutUint16(q[2:], 0x8180)
					binary.BigEndian.PutUint16(q[6:], 0)
					binary.BigEndian.PutUint16(q[8:], 0)
					binary.BigEndian.PutUint16(q[10:], 0)
					if qtype == 1 {
						binary.BigEndian.PutUint16(q[6:], 1)
						q = append(q, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 10, 1, 2, 3)
					}
					binary.BigEndian.PutUint16(size[:], uint16(len(q)))
					if _, e := io.Copy(c, bytes.NewReader(append(size[:], q...))); e != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { l.Close(); <-stopped; workers.Wait() })
	return l.Addr().String()
}
