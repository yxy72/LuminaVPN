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

	"netlaunch/internal/policy"
)

func TestPersonalSelectionUsesMixedIngressAndVerifiesTLS(t *testing.T) {
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
	client := personalProbeClient(proxy.Listener.Addr().String())
	defer client.CloseIdleConnections()
	probes := []policy.Probe{
		{URL: "https://company.must-not-contact.invalid/", Channel: "company"},
		{URL: "https://" + host + "/probe", Channel: "personal"},
		{URL: "https://direct.must-not-contact.invalid/", Channel: "direct"},
	}
	if e := verifyPersonalSelection(context.Background(), client, probes); e == nil || !strings.Contains(e.Error(), "certificate verification failed") {
		t.Fatal("untrusted target certificate accepted", e)
	}
	if requests.Load() != 0 || connects.Load() != 1 {
		t.Fatal("certificate failure allowed an HTTP request")
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	client.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots
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
		probes[1].Purpose, probes[1].ExpectedStatus = tc.purpose, tc.expected
		e := verifyPersonalSelection(context.Background(), client, probes)
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
