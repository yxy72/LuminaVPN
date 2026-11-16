//go:build darwin

package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
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

func TestDarwinPinnedCorePreservesFakeIPAcrossReloadAndPersonalDirect(t *testing.T) {
	root := os.Getenv("NETLAUNCH_TEST_RUNTIME")
	if root == "" {
		t.Skip("set NETLAUNCH_TEST_RUNTIME for the pinned core fixture")
	}
	if err := requireDarwinReloadCore(root); err != nil {
		t.Fatal(err)
	}
	testDarwinFakeIPContinuity(t, filepath.Join(root, "bin", "mihomo"), true)
}

func TestDarwinLegacyCoreReusesAssignedFakeIPOnResolverReload(t *testing.T) {
	root := os.Getenv("NETLAUNCH_TEST_MAC_LEGACY_RUNTIME")
	if root == "" {
		t.Skip("set NETLAUNCH_TEST_MAC_LEGACY_RUNTIME to reproduce the legacy allocator defect")
	}
	manifest, err := runtimebundle.Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Mihomo != "v1.19.32" {
		t.Fatalf("expected the original macOS Mihomo bundle, got %q", manifest.Mihomo)
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
	const alpha, beta, gamma, company, direct = "old.personal.example", "new.personal.example", "later.personal.example", "blocked.company.example", "direct.example"
	const secret = "loopback-fixture-controller-secret"
	held := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			held <- struct{}{}
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
			return
		}
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
			time.Sleep(5 * time.Millisecond)
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
		nodes := []policy.Node{{"name": "P001", "type": "hysteria2", "server": "192.0.2.77", "port": 443, "password": "fixture-only"}}
		manifest := Manifest{Mode: Daily, Channels: &policy.ChannelIntent{Personal: personal}, Config: cfg,
			Binding: policy.Binding{Physical: "lo0", VPN: "utun50", TUN: "utun51", ControllerPort: controllerPort}}
		var verification *personalVerification
		if personal {
			verification = &personalVerification{}
		}
		result, err := darwinCoreConfig(manifest, nodes, secret, nil, verification, false)
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
		dns["default-nameserver"] = []string{loopback}
		for _, key := range []string{"nameserver", "proxy-server-nameserver", "direct-nameserver"} {
			dns[key] = []string{loopback + "#PHYSICAL"}
		}
		dnsPolicy := dns["nameserver-policy"].(map[string]any)
		for host, record := range dnsPolicy {
			switch server := record.([]string)[0]; {
			case server == "rcode://refused":
			case strings.HasSuffix(server, "#PERSONAL"):
				// Explicit Personal Off uses the separate direct DNS policy.
				dnsPolicy[host] = []string{"rcode://refused"}
			default:
				dnsPolicy[host] = []string{loopback + "#PHYSICAL"}
			}
		}
		return result
	}
	dir := testutil.PrivateTempDir(t)
	file := filepath.Join(dir, "core.json")
	previous := config(true)
	if err := securefile.Write(file, previous); err != nil {
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
	selectGroup := func(group, name string) error {
		if err := api(ctx, "PUT", "/proxies/"+group, map[string]string{"name": name}, nil); err != nil {
			return err
		}
		var selected struct{ Now string }
		if err := api(ctx, "GET", "/proxies/"+group, nil, &selected); err != nil {
			return err
		}
		if selected.Now != name {
			return fmt.Errorf("%s = %q, want %q", group, selected.Now, name)
		}
		return nil
	}
	choose := func(name string) {
		t.Helper()
		if err := selectGroup("PERSONAL", name); err != nil {
			t.Fatal(err)
		}
	}
	open := func(direct bool) {
		t.Helper()
		if err := openDesktopConfig(selectGroup, direct); err != nil {
			t.Fatal(err)
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
	reload := func(personal bool, failure error) error {
		t.Helper()
		next := config(personal)
		err := prepareDarwinPersonalConfig(next, previous, file, desktopReloadControl{
			selectGroup: selectGroup,
			request: func(method, path string, payload, out any) error {
				if path == "/cache/dns/flush" && failure != nil {
					return failure
				}
				return api(ctx, method, path, payload, out)
			},
			save: func(config map[string]any) error { return securefile.Write(file, config) },
		})
		assertNoTUN()
		if err == nil || errors.Is(err, failure) {
			previous = next
		}
		return err
	}

	open(false)
	first, denied := lookup(alpha), lookup(company)
	// Before any candidate is chosen, the base path is usable and neither
	// the unverified personal target nor the disabled company target can dial.
	request(lookup(direct), "physical")
	request(first, "")
	request(denied, "")
	choose("P001")
	request(first, "personal")
	seenProxy(alpha)
	request(denied, "")
	if err := reload(true, nil); err != nil {
		t.Fatal(err)
	}
	open(false)
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
	physicalAddress := lookup(direct)
	request(physicalAddress, "physical")
	flushUnavailable := errors.New("injected resolver flush failure")
	if err := reload(false, flushUnavailable); !errors.Is(err, flushUnavailable) {
		t.Fatal("expected resolver flush failure", err)
	}
	request(physicalAddress, "")
	request(first, "")

	if err := reload(false, nil); err != nil {
		t.Fatal(err)
	}
	request(first, "")
	request(physicalAddress, "")
	open(true)
	request(first, "physical") // Exercise the held address without issuing a new DNS lookup.
	request(second, "physical")
	request(denied, "")
	third := lookup(gamma)
	if lookup(alpha) != first || lookup(beta) != second || lookup(company) != denied || third == first || third == second || third == denied {
		t.Fatal("personal direct reload changed an address or aliased a new host")
	}
	request(third, "physical")
	var delay struct{ Delay int }
	query := url.Values{"url": {"http://" + target.Listener.Addr().String() + "/check"}, "timeout": {"2000"}, "expected": {"200-599"}}
	if err := api(ctx, "GET", "/proxies/P001/delay?"+query.Encode(), nil, &delay); err != nil || delay.Delay < 1 {
		t.Fatal("fallback removed independent candidate health", delay.Delay, err)
	}
	seenProxy("127.0.0.1")
	if err := selectGroup("PERSONAL", "P001"); err == nil {
		t.Fatal("fallback exposed a candidate through the ordinary PERSONAL route")
	}
	if err := api(ctx, "GET", "/proxies/"+candidateGroup, nil, nil); err == nil {
		t.Fatal("fallback kept its isolated candidate ingress group")
	}
	select {
	case got := <-vias:
		t.Fatalf("direct mode unexpectedly used the personal proxy for %s", got)
	default:
	}

	// Revoke a real, tracked Personal→PHYSICAL flow before changing DNS.
	connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", mixedAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	dst := net.JoinHostPort(first.String(), strconv.Itoa(port))
	_, _ = fmt.Fprintf(connection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dst, dst)
	reader := bufio.NewReader(connection)
	if tunnel, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect}); err != nil || tunnel.StatusCode != http.StatusOK {
		t.Fatal("could not create the held personal fallback connection", err)
	}
	_, _ = fmt.Fprintf(connection, "GET /hold HTTP/1.1\r\nHost: %s\r\n\r\n", dst)
	select {
	case <-held:
	case <-time.After(time.Second):
		t.Fatal("fixture did not establish the physical fallback connection")
	}
	choose("REJECT")
	if err := drainDarwinFallbackConnections(func(method, path string, payload, out any) error {
		return api(ctx, method, path, payload, out)
	}); err != nil {
		t.Fatal(err)
	}
	_, err = reader.ReadByte()
	var timedOut net.Error
	if err == nil || errors.As(err, &timedOut) && timedOut.Timeout() {
		t.Fatalf("the old fallback connection was not immediately retired: %v", err)
	}
	if err := reload(true, nil); err != nil {
		t.Fatal(err)
	}
	request(first, "")
	request(physicalAddress, "")
	open(false)
	request(physicalAddress, "physical")
	request(first, "") // The coordinator must verify a candidate before selecting it.
	choose("P001")
	request(first, "personal")
	seenProxy(alpha)
	request(denied, "")
}
