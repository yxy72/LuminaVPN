//go:build darwin || windows

package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSamplingDistinguishesCoreErrorsAndTargetResults(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		history string
		known   bool
		success bool
	}{
		{"authentication", 401, "private-body", "", false, false},
		{"missing_node", 404, "private-body", "", false, false},
		{"core_error", 500, "private-body", "", false, false},
		{"target_failed", 503, "private-body", "", true, false},
		{"target_timeout", 504, "private-body", "", true, false},
		{"invalid_json", 200, "private-body", "", false, false},
		{"missing_delay", 200, `{}`, "", false, false},
		{"missing_history", 200, `{"delay":12}`, `{}`, false, false},
		{"missing_alive", 200, `{"delay":12}`, `{"history":[{"time":%q,"delay":12}]}`, false, false},
		{"success", 200, `{"delay":12}`, `{"alive":true,"history":[{"time":%q,"delay":12}]}`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const target = "https://target.example/"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/delay") {
					if r.URL.Query().Get("expected") != "200-599" {
						t.Error("latency ranking applied service expectations")
					}
					w.WriteHeader(tc.status)
					fmt.Fprint(w, tc.body)
				} else {
					value := tc.history
					if strings.Contains(value, "%q") {
						value = fmt.Sprintf(value, time.Now().Format(time.RFC3339Nano))
					}
					if value == "" {
						value = "{}"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"extra": map[string]json.RawMessage{target: json.RawMessage(value)}})
				}
			}))
			defer server.Close()
			request := func(ctx context.Context, path string, out any) error {
				return coreRequest(ctx, strings.TrimPrefix(server.URL, "http://"), "fixture", "GET", path, nil, out)
			}
			values := measurePersonalWith(context.Background(), []string{"node"}, []string{target}, request)
			value, known := values["node"]
			if known != tc.known || known && (value >= 0) != tc.success {
				t.Fatal("incorrect measurement", values)
			}
		})
	}
}

func TestControlTransportFailureDoesNotBecomeNodeFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	address := strings.TrimPrefix(server.URL, "http://")
	server.Close()
	request := func(ctx context.Context, path string, out any) error {
		return coreRequest(ctx, address, "fixture", "GET", path, nil, out)
	}
	if values := measurePersonalWith(context.Background(), []string{"node"}, []string{"https://target.example/"}, request); len(values) != 0 {
		t.Fatal(values)
	}
}
