//go:build darwin

package engine

import (
	"bufio"
	"bytes"
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
	"strconv"
	"strings"
	"testing"
	"time"

	"netlaunch/internal/policy"
	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/securefile"
	"netlaunch/internal/testutil"
)

func fakeIPQuestion(host string) []byte {
	query := []byte{0x4b, 0x2e, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(host, ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	return append(query, 0, 0, 1, 0, 1)
}

func fakeIPFixturePort(t *testing.T) *net.UDPConn {
	t.Helper()
	resolver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resolver.Close() })
	return resolver
}

func serveFakeIPFixtureDNS(t *testing.T, resolver *net.UDPConn) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 2048)
		for {
			size, source, err := resolver.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if size < 17 || binary.BigEndian.Uint16(buffer[4:]) != 1 {
				continue
			}
			end := bytes.IndexByte(buffer[12:size], 0) + 17
			if end < 17 || end > size {
				continue
			}
			reply := append([]byte(nil), buffer[:end]...)
			reply[2], reply[3] = 0x81, 0x80
			clear(reply[6:12])
			if binary.BigEndian.Uint16(reply[end-4:]) == 1 {
				reply[7] = 1
				reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1)
			}
			if _, err := resolver.WriteToUDP(reply, source); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = resolver.Close()
		<-done
	})
}

func TestDarwinPinnedCoreReusesAssignedFakeIPOnResolverReload(t *testing.T) {
	root := os.Getenv("NETLAUNCH_TEST_RUNTIME")
	if root == "" {
		t.Skip("set NETLAUNCH_TEST_RUNTIME for the pinned core fixture")
	}
	if _, err := runtimebundle.Verify(root); err != nil {
		t.Fatal(err)
	}
	testDarwinFakeIPContinuity(t, filepath.Join(root, "bin", "mihomo"), false)
}

func TestDarwinRebuiltCorePreservesFakeIPAcrossReloadAndPersonalDirect(t *testing.T) {
	executable := os.Getenv("NETLAUNCH_TEST_MIHOMO_REBUILD")
	if executable == "" {
		t.Skip("set NETLAUNCH_TEST_MIHOMO_REBUILD to the reviewed source rebuild")
	}
	testDarwinFakeIPContinuity(t, executable, true)
}

func testDarwinFakeIPContinuity(t *testing.T, executable string, preservesPool bool) {
	const alpha, beta, gamma, company = "old.personal.example", "new.personal.example", "later.personal.example", "blocked.company.example"
	const secret = "loopback-fixture-controller-secret"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/check" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, "physical")
	}))
	defer target.Close()
	vias := make(chan string, 12)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "expected CONNECT", http.StatusBadRequest)
			return
		}
		select {
		case vias <- r.Host:
		default:
			t.Error("fixture received too many proxy connections")
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = rw.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		if err := rw.Flush(); err != nil {
			return
		}
		if _, err := http.ReadRequest(rw.Reader); err == nil {
			_, _ = rw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\npersonal")
			_ = rw.Flush()
		}
	}))
	defer proxy.Close()
	upstream := fakeIPFixturePort(t)
	serveFakeIPFixtureDNS(t, upstream)
	dns := fakeIPFixturePort(t)
	dnsAddress := dns.LocalAddr().(*net.UDPAddr)
	_ = dns.Close()
	control := httptest.NewUnstartedServer(nil)
	mixed := httptest.NewUnstartedServer(nil)
	controlAddress, mixedAddress := control.Listener.Addr().String(), mixed.Listener.Addr().String()
	mixedPort := mixed.Listener.Addr().(*net.TCPAddr).Port
	controllerPort := control.Listener.Addr().(*net.TCPAddr).Port
	_ = control.Listener.Close()
	_ = mixed.Listener.Close()
	cfg := policy.Config{
		Version: 1, Ports: policy.Ports{Proxy: mixedPort, DNS: dnsAddress.Port},
		Company:   policy.Channel{Domains: []string{company}},
		Personal:  policy.Channel{Domains: []string{alpha, beta, gamma}, DNS: []string{"https://192.0.2.54/dns-query"}},
		DirectDNS: []string{"192.0.2.53"},
		Probes:    []policy.Probe{{Channel: "direct", URL: "https://direct.example/check"}, {Channel: "personal", URL: "https://" + alpha + "/check"}},
	}
	config := func(personal bool) map[string]any {
		t.Helper()
		var nodes []policy.Node
		if personal {
			nodes = []policy.Node{{"name": "P001", "type": "hysteria2", "server": "192.0.2.77", "port": 443, "password": "fixture-only"}}
		}
		manifest := Manifest{Mode: Daily, Channels: &policy.ChannelIntent{Personal: personal}, Config: cfg,
			Binding: policy.Binding{Physical: "lo0", VPN: "utun50", TUN: "utun51", ControllerPort: controllerPort}}
		var verification *personalVerification
		if personal {
			verification = &personalVerification{}
		}
		result, err := darwinCoreConfig(manifest, nodes, secret, nil, verification)
		if err != nil {
			t.Fatal(err)
		}
		// Reuse the generated rules and groups. The fixture substitutes only its
		// controlled loopback backends for configured addresses and credentials.
		delete(result, "listeners")
		delete(result, "sub-rules")
		// Candidate ingress is outside this fixture; its guard remains harmless.
		for _, raw := range result["proxies"].([]any) {
			if item, ok := raw.(policy.Node); ok {
				delete(item, "password")
				item["type"], item["server"], item["port"] = "http", "127.0.0.1", proxy.Listener.Addr().(*net.TCPAddr).Port
			}
		}
		dns := result["dns"].(map[string]any)
		loopback := "udp://" + upstream.LocalAddr().String()
		for _, key := range []string{"nameserver", "default-nameserver", "proxy-server-nameserver", "direct-nameserver"} {
			dns[key] = []string{loopback}
		}
		dnsPolicy := dns["nameserver-policy"].(map[string]any)
		for host, record := range dnsPolicy {
			switch server := record.([]string)[0]; {
			case server == "rcode://refused":
			case strings.HasSuffix(server, "#PERSONAL"):
				// A fallback that still depends on the personal DNS policy
				// must fail, even if it selects the direct data path.
				dnsPolicy[host] = []string{"rcode://refused"}
			default:
				dnsPolicy[host] = []string{loopback}
			}
		}
		return result
	}
	dir := testutil.PrivateTempDir(t)
	file := filepath.Join(dir, "core.json")
	if err := securefile.Write(file, config(true)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-d", dir, "-f", file)
	log := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("loopback core log:\n%s", log.String())
		}
	}()
	api := func(ctx context.Context, method, path string, payload, out any) error {
		return coreRequest(ctx, controlAddress, secret, method, path, payload, out)
	}
	if err := waitReady(ctx, 4*time.Second, func() error { return nil }, func(c context.Context) error {
		return api(c, "GET", "/version", nil, nil)
	}); err != nil {
		t.Fatal(err)
	}
	assertNoTUN := func() {
		t.Helper()
		var active struct{ TUN struct{ Enable bool } }
		if err := api(ctx, "GET", "/configs", nil, &active); err != nil || active.TUN.Enable {
			t.Fatal("fixture unexpectedly enabled TUN", err)
		}
	}
	assertNoTUN()
	choose := func(name string) {
		t.Helper()
		if err := api(ctx, "PUT", "/proxies/PERSONAL", map[string]string{"name": name}, nil); err != nil {
			t.Fatal(err)
		}
		var selected struct{ Now string }
		if err := api(ctx, "GET", "/proxies/PERSONAL", nil, &selected); err != nil || selected.Now != name {
			t.Fatalf("personal selection = %q, %v", selected.Now, err)
		}
	}
	lookup := func(host string) netip.Addr {
		t.Helper()
		conn, err := net.DialUDP("udp4", nil, dnsAddress)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		question := fakeIPQuestion(host)
		if _, err := conn.Write(question); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 1500)
		size, err := conn.Read(buffer)
		if err != nil || size < len(question)+16 || binary.BigEndian.Uint16(buffer[6:]) != 1 {
			t.Fatalf("fake-IP answer for %s: %d bytes, %v", host, size, err)
		}
		answer := netip.AddrFrom4([4]byte(buffer[size-4 : size]))
		if !netip.MustParsePrefix("198.19.0.0/16").Contains(answer) {
			t.Fatalf("unexpected fake-IP for %s: %v", host, answer)
		}
		return answer
	}
	port := target.Listener.Addr().(*net.TCPAddr).Port
	request := func(address netip.Addr, via string) {
		t.Helper()
		conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp4", mixedAddress)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		dst := net.JoinHostPort(address.String(), strconv.Itoa(port))
		_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dst, dst)
		reader := bufio.NewReader(conn)
		tunnel, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
		if err != nil || tunnel.StatusCode != http.StatusOK {
			if via == "" {
				return
			}
			t.Fatalf("could not connect from %s to %s: %v", mixedAddress, dst, err)
		}
		_, _ = fmt.Fprintf(conn, "GET /check HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", dst)
		response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
		if via == "" && err != nil {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 64))
		if err != nil || string(body) != via {
			t.Fatalf("fake-IP %s left through %q, want %q: %v", address, body, via, err)
		}
	}
	seenProxy := func(host string) {
		t.Helper()
		select {
		case got := <-vias:
			if want := net.JoinHostPort(host, strconv.Itoa(port)); got != want {
				t.Fatalf("reverse fake-IP mapping = %s, want %s", got, want)
			}
		default:
			t.Fatal("request did not use the personal proxy")
		}
	}
	reload := func(personal, flushResolver bool) {
		t.Helper()
		choose("REJECT")
		if err := securefile.Write(file, config(personal)); err != nil {
			t.Fatal(err)
		}
		if err := api(ctx, "PUT", "/configs?force=true", map[string]string{"path": file}, nil); err != nil {
			t.Fatal(err)
		}
		assertNoTUN()
		choose("REJECT")
		if flushResolver {
			if err := api(ctx, "POST", "/cache/dns/flush", nil, nil); err != nil {
				t.Fatal(err)
			}
		}
	}

	choose("P001")
	first, denied := lookup(alpha), lookup(company)
	request(first, "personal")
	seenProxy(alpha)
	request(denied, "")
	reload(true, false)
	choose("P001")
	second := lookup(beta)
	if !preservesPool {
		// Without the patch, the new allocator reuses both addresses while
		// their former owners' clients may still be holding the answers.
		if other := lookup(gamma); second != first || other != denied {
			t.Fatalf("pinned core behavior changed: first=%s next=%s denied=%s other=%s", first, second, denied, other)
		}
		request(first, "personal")
		seenProxy(beta)
		request(denied, "personal")
		seenProxy(gamma)
		t.Log("pinned core rerouted the previously blocked synthetic address after an unchanged reload")
		return
	}
	if held, blocked := lookup(alpha), lookup(company); held != first || blocked != denied || second == first || second == denied {
		t.Fatalf("resolver reload first=%s held=%s blocked=%s blocked-after=%s new=%s", first, held, denied, blocked, second)
	}
	request(first, "personal")
	seenProxy(alpha)
	reload(false, true)
	request(first, "") // The selected route stays closed until the caller opens PHYSICAL.
	choose("PHYSICAL")
	request(first, "physical") // Exercise the held address without issuing a new DNS lookup.
	request(second, "physical")
	request(denied, "")
	third := lookup(gamma)
	if lookup(alpha) != first || lookup(beta) != second || lookup(company) != denied || third == first || third == second || third == denied {
		t.Fatal("personal direct reload changed an address or aliased a new host")
	}
	request(third, "physical")
	select {
	case got := <-vias:
		t.Fatalf("direct mode unexpectedly used the personal proxy for %s", got)
	default:
	}
}
