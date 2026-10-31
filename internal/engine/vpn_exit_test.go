//go:build darwin || windows

package engine

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/runtimebundle"
)

// The pinned client talks only to a local TLS server, using a dummy cookie.
// Both responses reject CSTP before any Wintun or hook can be initialized.
func TestPinnedOpenConnectDistinguishesRejectedCookie(t *testing.T) {
	root := os.Getenv("NETLAUNCH_TEST_RUNTIME")
	if root == "" {
		t.Skip("set NETLAUNCH_TEST_RUNTIME for the pinned client fixture")
	}
	if _, err := runtimebundle.Verify(root); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ status, exit int }{{401, 2}, {503, 1}} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			var connects atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodConnect {
					connects.Add(1)
				}
				w.WriteHeader(tc.status)
			}))
			defer server.Close()
			ca := filepath.Join(t.TempDir(), "loopback-ca.pem")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			program := "openconnect"
			if runtime.GOOS == "windows" {
				program += ".exe"
			}
			cmd := exec.CommandContext(ctx, filepath.Join(root, "bin", program), "--protocol=anyconnect", "--non-inter", "--cookie-on-stdin", "--no-dtls", "--no-proxy", "--no-system-trust", "--cafile="+ca, server.URL)
			hideVPNFixtureWindow(cmd)
			cmd.Env = append(os.Environ(), "OPENSSL_CONF="+os.DevNull)
			cmd.Stdin = strings.NewReader("loopback-fixture-cookie\n")
			var log bytes.Buffer
			cmd.Stdout, cmd.Stderr = &log, &log
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || ctx.Err() != nil || (runtime.GOOS == "windows" && exit.ExitCode() != tc.exit) || connects.Load() != 1 {
				t.Fatalf("pinned client classification: exit=%v connects=%d deadline=%v", err, connects.Load(), ctx.Err())
			}
			classified := vpnFailureCode(log.String())
			if (tc.status == 401) != (classified == "authentication_rejected") {
				t.Fatal("pinned client log classification:", classified)
			}
		})
	}
}

func TestChildExitIgnoresReplacedAttempt(t *testing.T) {
	g := &childExitTracker{}
	releaseOld, releaseNew := make(chan struct{}), make(chan struct{})
	g.trackExit("vpn", platform.Identity{PID: 10, Birth: "old"}, func() (uint32, error) { <-releaseOld; return 2, nil })
	old := g.exits["vpn"]
	g.trackExit("vpn", platform.Identity{PID: 11, Birth: "new"}, func() (uint32, error) { <-releaseNew; return 1, nil })
	fresh := g.exits["vpn"]
	close(releaseOld)
	<-old.done
	if g.vpnAuthenticationRejected() {
		t.Fatal("late old exit revoked a new pending attempt")
	}
	close(releaseNew)
	<-fresh.done
	if g.vpnAuthenticationRejected() {
		t.Fatal("transient failure classified as authentication rejection")
	}
	result, known := g.childExit("vpn")
	if !known || result.identity.PID != 11 {
		t.Fatal("exit result belongs to another attempt")
	}
}

func TestChildExitClassifiesOnlyKnownCurrentVPNResult(t *testing.T) {
	for _, tc := range []struct {
		role     string
		code     uint32
		err      error
		rejected bool
	}{
		{"vpn", 2, nil, true}, {"vpn", 2, errors.New("exit query failed"), false}, {"vpn", 0, nil, false}, {"vpn", 1, nil, false}, {"core", 2, nil, false},
	} {
		g := &childExitTracker{}
		g.trackExit(tc.role, platform.Identity{PID: 10}, func() (uint32, error) { return tc.code, tc.err })
		<-g.exits[tc.role].done
		if g.vpnAuthenticationRejected() != tc.rejected {
			t.Fatal("incorrect exit classification", tc.role, tc.code, tc.err)
		}
		// Accepting new local authentication clears the old result. Its waiter
		// cannot republish into the map after a replacement or removal.
		delete(g.exits, "vpn")
		if g.vpnAuthenticationRejected() {
			t.Fatal("old session still blocks refreshed authentication")
		}
	}
	if !errors.Is(&terminalReadinessError{errVPNAuthenticationRequired}, errVPNAuthenticationRequired) {
		t.Fatal("terminal bootstrap lost its authentication cause")
	}
}
