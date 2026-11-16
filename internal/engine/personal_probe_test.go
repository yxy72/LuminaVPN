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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"netlaunch/internal/policy"
)

func TestPersonalSelectionUsesAuthenticatedLoopbackAndVerifiesTLS(t *testing.T) {
	var requests, connects atomic.Int32
	var status atomic.Int32
	status.Store(http.StatusNoContent)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodHead || r.URL.Path != "/probe" {
			t.Error("unexpected personal request", r.Method, r.URL.Path)
		}
		w.Header().Set("Location", "https://must-not-follow.invalid/")
		w.WriteHeader(int(status.Load()))
	}))
	defer target.Close()
	certificate := target.Certificate()
	host := certificate.DNSNames[0]
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connects.Add(1)
		if r.Header.Get("Proxy-Authorization") != "Basic bHVtaW5hLXByb2JlOmZpeHR1cmUtcGFzcw==" {
			t.Error("probe did not authenticate to its loopback listener")
		}
		if r.Method != http.MethodConnect || r.Host != host+":443" {
			t.Error("probe escaped expected CONNECT target", r.Method, r.Host)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		upstream, e := net.Dial("tcp", target.Listener.Addr().String())
		if e != nil {
			t.Error(e)
			return
		}
		defer upstream.Close()
		client, _, e := w.(http.Hijacker).Hijack()
		if e != nil {
			t.Error(e)
			return
		}
		defer client.Close()
		fmt.Fprint(client, "HTTP/1.1 200 Connection established\r\n\r\n")
		done := make(chan struct{})
		go func() { io.Copy(upstream, client); upstream.Close(); close(done) }()
		io.Copy(client, upstream)
		client.Close()
		<-done
	}))
	defer proxy.Close()
	probe := policy.Probe{URL: "https://" + host + "/probe", Channel: "personal"}
	port := proxy.Listener.Addr().(*net.TCPAddr).Port
	dial := func(ctx context.Context, host string, targetPort int) (net.Conn, error) {
		return connectProbeIngress(ctx, port, host, targetPort, candidateUser, "fixture-pass")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if e := probeHTTPS(ctx, probe, dial, nil, nil); e == nil || !strings.Contains(e.Error(), "certificate verification failed") {
		t.Fatal("untrusted target certificate accepted", e)
	}
	if requests.Load() != 0 || connects.Load() != 1 {
		t.Fatal("certificate failure allowed an HTTP request")
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	cases := []struct {
		code     int
		purpose  string
		expected []int
		pass     bool
	}{
		{204, "", nil, true}, {302, "", nil, true}, {403, "", nil, false},
		{503, "path", nil, true}, {503, "service", nil, false},
		{401, "service", []int{204, 401}, true}, {200, "service", []int{204}, false},
	}
	for _, tc := range cases {
		status.Store(int32(tc.code))
		probe.Purpose, probe.ExpectedStatus = tc.purpose, tc.expected
		e := probeHTTPS(ctx, probe, dial, nil, roots)
		if (e == nil) != tc.pass {
			t.Fatal("wrong personal status result", tc, e)
		}
		if e != nil && (probeReason(e) != "http_status_rejected" || nodeProbeFailure(e)) {
			t.Fatal("service failure blamed node", e)
		}
	}
	if requests.Load() != int32(len(cases)) || connects.Load() != int32(len(cases)+1) {
		t.Fatal("requests were reused, redirected or sent to a non-personal target", requests.Load(), connects.Load())
	}
}
