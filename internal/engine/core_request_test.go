//go:build darwin || windows

package engine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCoreRequestCancellationReachesServer(t *testing.T) {
	for _, bodyStarted := range []bool{false, true} {
		t.Run(map[bool]string{false: "headers", true: "body"}[bodyStarted], func(t *testing.T) {
			entered, gone := make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer fixture-secret" {
					t.Error("missing controller authorization")
				}
				if bodyStarted {
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
				}
				close(entered)
				<-r.Context().Done()
				close(gone)
			}))
			defer server.Close()
			defer server.CloseClientConnections()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var out map[string]any
				done <- coreRequest(ctx, strings.TrimPrefix(server.URL, "http://"), "fixture-secret", "GET", "/configs", nil, &out)
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("request never reached fixture")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation waited for the independent five-second timeout")
			}
			select {
			case <-gone:
			case <-time.After(time.Second):
				t.Fatal("request remained open after cancellation")
			}
		})
	}
}

func TestCoreRequestRejectsNonLocalAuthority(t *testing.T) {
	for _, address := range []string{"localhost:1234", "127.0.0.1:80@example.invalid", "127.0.0.1:0", "192.0.2.1:1234"} {
		if err := coreRequest(context.Background(), address, "fixture-secret", "GET", "/configs", nil, nil); err == nil {
			t.Fatal("accepted invalid local controller", address)
		}
	}
}
