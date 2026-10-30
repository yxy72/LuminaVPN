package subscription

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netlaunch/internal/policy"
)

const nodeFixture = `proxies:
- {type: vless, server: 203.0.113.7, port: 443, uuid: "11111111-1111-1111-1111-111111111111", tls: true, interface-name: evil, dialer-proxy: evil}
- {type: ss, server: 203.0.113.8, port: 443, password: fixture}
rules: ["DOMAIN-SUFFIX,example.org,Custom", "DOMAIN,blocked.example.org,REJECT", "MATCH,DIRECT"]
dns: {nameserver: [evil]}
tun: {enable: true}
rule-providers: {evil: {url: "https://must-not-fetch.invalid/"}}
`

func bootstrap(t *testing.T) Bootstrap {
	t.Helper()
	b, e := os.ReadFile("../../examples/policy.json")
	if e != nil {
		t.Fatal(e)
	}
	c, e := policy.Decode(b)
	if e != nil {
		t.Fatal(e)
	}
	return Bootstrap{Version: 1, Policy: c, Subscriptions: Sources{Nodes: Source{File: "nodes.yaml"}}}
}
func TestBootstrapValidationAndRelativePaths(t *testing.T) {
	b := bootstrap(t)
	raw, _ := json.Marshal(b)
	base := t.TempDir()
	got, e := Decode(raw, base)
	if e != nil || got.Subscriptions.Nodes.File != filepath.Join(base, "nodes.yaml") || got.Subscriptions.IntervalMinutes != 60 {
		t.Fatal(got, e)
	}
	for _, mutate := range []func(*Bootstrap){
		func(b *Bootstrap) { b.Version = 2 },
		func(b *Bootstrap) { b.Subscriptions.Nodes.URL = "https://source.example.com/" },
		func(b *Bootstrap) {
			b.Subscriptions.Nodes = Source{URL: "http://source.example.com/?token=fixture-secret"}
		},
		func(b *Bootstrap) {
			b.Subscriptions.Nodes = Source{URL: "https://user:fixture-secret@source.example.com/"}
		},
		func(b *Bootstrap) { b.Subscriptions.Nodes.Groups = map[string]string{"X": "company"} },
		func(b *Bootstrap) { b.Subscriptions.IntervalMinutes = -1 },
	} {
		b := bootstrap(t)
		mutate(&b)
		raw, _ := json.Marshal(b)
		if _, e := Decode(raw, base); e == nil || strings.Contains(e.Error(), "fixture-secret") {
			t.Fatal("invalid bootstrap accepted or secret disclosed", e)
		}
	}
	for _, raw := range [][]byte{[]byte(`{"version":1,"session":"fixture-secret"}`), []byte(strings.Repeat("x", (1<<20)+1))} {
		if _, e := Decode(raw, base); e == nil {
			t.Fatal("invalid input accepted")
		}
	}
}
func TestFetchExtractsOnlyExplicitNodesAndRules(t *testing.T) {
	s := Sources{Nodes: Source{URL: "https://source.example.com/", UseRules: true, Groups: map[string]string{"Custom": "personal"}}, Rules: []Source{{File: "extra.yaml", Format: "domain", Target: "direct"}}}
	calls := 0
	result, e := FetchWith(context.Background(), s, func(_ context.Context, source Source) ([]byte, error) {
		calls++
		if source.File != "" {
			return []byte("payload: ['+.extra.example.org']"), nil
		}
		return []byte(nodeFixture), nil
	})
	if e != nil || calls != 2 || len(result.Nodes) != 1 || len(result.Rules) != 3 || result.SkippedNodes != 1 || result.SkippedRules != 1 {
		t.Fatal(result, calls, e)
	}
	for _, key := range []string{"interface-name", "dialer-proxy", "dns", "tun", "rules"} {
		if _, ok := result.Nodes[0][key]; ok {
			t.Fatal("inherited settings", key)
		}
	}
	if result.Rules[0] != (policy.Rule{Type: "DOMAIN-SUFFIX", Value: "example.org", Target: "personal"}) {
		t.Fatal(result.Rules)
	}
	s.Nodes.UseRules = false
	s.Rules = nil
	result, e = FetchWith(context.Background(), s, func(context.Context, Source) ([]byte, error) { return []byte(nodeFixture), nil })
	if e != nil || len(result.Rules) != 0 {
		t.Fatal("rules imported without opt-in", e)
	}
}
func TestRuleParserDoesNotApproximateUnsupportedSyntax(t *testing.T) {
	data := `payload:
- DOMAIN,valid.example.org,PROXY
- DOMAIN,wrong.example.org,PROXY,no-resolve
- DOMAIN,wrong2.example.org,no-resolve
- DOMAIN,wrong3.example.org,Unknown
- DOMAIN-SUFFIX,suffix.example.org,DIRECT
- IP-CIDR,203.0.113.0/24,PROXY,no-resolve
- IP-CIDR,203.0.112.0/24,no-resolve
- IP-CIDR,203.0.111.0/24,no-resolve,no-resolve
- IP-CIDR,10.0.0.0/8,PROXY
- DOMAIN-KEYWORD,example,PROXY
- IP-CIDR6,2001:db8::/32,PROXY
- MATCH,PROXY
`
	r, skipped, e := ParseRules([]byte(data), Source{})
	if e != nil || len(r) != 4 || skipped != 8 {
		t.Fatal(r, skipped, e)
	}
	for _, data := range []string{`payload: []`, `payload: ['MATCH,DIRECT']`, `payload: [true]`} {
		if _, _, e := ParseRules([]byte(data), Source{}); e == nil {
			t.Fatal("unsupported source accepted")
		}
	}
	r, skipped, e = ParseRules([]byte(`payload: ['+.example.org','exact.example.org','*.unsupported.org']`), Source{Format: "domain", Target: "reject"})
	if e != nil || len(r) != 2 || skipped != 1 || r[0].Target != "reject" {
		t.Fatal(r, skipped, e)
	}
}
func TestSourceReadBoundsAndRedacts(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "source.yaml")
	if e := os.WriteFile(path, []byte(strings.Repeat("x", (4<<20)+1)), 0600); e != nil {
		t.Fatal(e)
	}
	for _, s := range []Source{{File: path}, {URL: "http://127.0.0.1/?token=fixture-secret"}, {URL: "https://user:fixture-secret@source.example.com/"}} {
		_, e := Read(context.Background(), s)
		if e == nil || strings.Contains(e.Error(), "fixture-secret") {
			t.Fatal(e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e := Read(ctx, Source{URL: "https://source.example.com/?token=fixture-secret"})
	if e == nil || strings.Contains(e.Error(), "fixture-secret") {
		t.Fatal(e)
	}
}

func TestHTTPSNoRedirectAndBoundedResponses(t *testing.T) {
	redirected := false
	next := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		w.Write([]byte("private-fixture-token"))
	}))
	defer next.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, next.URL, http.StatusFound)
		case "/large":
			w.Write([]byte(strings.Repeat("x", (4<<20)+1)))
		case "/denied":
			w.WriteHeader(403)
			w.Write([]byte("private-fixture-token"))
		default:
			w.Write([]byte("proxies: []"))
		}
	}))
	defer source.Close()
	for _, path := range []string{"/redirect", "/large", "/denied"} {
		_, e := readHTTPS(context.Background(), Source{URL: source.URL + path + "?token=private-fixture-token"}, source.Client().Transport)
		if e == nil || strings.Contains(e.Error(), "private-fixture-token") {
			t.Fatal("invalid response accepted or disclosed", e)
		}
	}
	if redirected {
		t.Fatal("redirect followed")
	}
	got, e := readHTTPS(context.Background(), Source{URL: source.URL}, source.Client().Transport)
	if e != nil || string(got) != "proxies: []" {
		t.Fatal(e)
	}
}
