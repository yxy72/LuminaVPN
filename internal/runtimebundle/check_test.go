package runtimebundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"netlaunch/internal/securefile"
	"netlaunch/internal/testutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func checkFixture(t *testing.T) string {
	t.Helper()
	root := testutil.PrivateTempDir(t)
	m := Manifest{Version: 1, OS: runtime.GOOS, Arch: runtime.GOARCH, Mihomo: "v1.19.32", OpenConnect: "9.21"}
	for _, name := range required(runtime.GOOS) {
		if e := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0700); e != nil {
			t.Fatal(e)
		}
		data := []byte("fixture " + name)
		if e := os.WriteFile(filepath.Join(root, name), data, 0600); e != nil {
			t.Fatal(e)
		}
		h := sha256.Sum256(data)
		m.Files = append(m.Files, File{name, hex.EncodeToString(h[:])})
	}
	if e := securefile.Write(filepath.Join(root, "manifest.json"), m); e != nil {
		t.Fatal(e)
	}
	return root
}

func TestRuntimeCheckRequiresWholeVerifiedBundle(t *testing.T) {
	root := checkFixture(t)
	if e := os.WriteFile(filepath.Join(root, required(runtime.GOOS)[1]), []byte("tampered"), 0600); e != nil {
		t.Fatal(e)
	}
	r, e := check(context.Background(), root, func(context.Context, string, string) (string, error) {
		t.Fatal("executed a client before the whole bundle was verified")
		return "", nil
	})
	if e == nil || r.BundleVerified || r.ClientsLoadable || len(r.Checks) != 0 {
		t.Fatal(r, e)
	}
}

func TestRuntimeCheckStopsOnFailureAndHonorsCancellation(t *testing.T) {
	for _, scenario := range []string{"execution_failed", "version_mismatch", "timeout_or_cancelled", "pass"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			r, e := check(ctx, checkFixture(t), func(ctx context.Context, path, arg string) (string, error) {
				calls++
				if !filepath.IsAbs(path) {
					t.Fatal("relative execution path")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("unbounded execution")
				}
				if calls == 1 && arg != "-v" || calls == 2 && arg != "--version" {
					t.Fatal("unexpected arguments", arg)
				}
				switch scenario {
				case "execution_failed":
					return "private diagnostic content", errors.New("private error")
				case "version_mismatch":
					return "Mihomo Meta v1.19.320", nil
				case "timeout_or_cancelled":
					cancel()
					return "", context.Canceled
				}
				if calls == 1 {
					return "Mihomo Meta v1.19.32 darwin arm64", nil
				}
				return "OpenConnect version v9.21\nUsing OpenSSL", nil
			})
			if scenario == "pass" {
				if e != nil || !r.ClientsLoadable || calls != 2 {
					t.Fatal(r, e, calls)
				}
			} else if e == nil || r.ClientsLoadable || calls != 1 || r.Checks[0].Status != scenario || strings.Contains(e.Error(), "private") {
				t.Fatal(r, e, calls)
			}
			if r.NetworkChanges {
				t.Fatal("claimed network changes")
			}
		})
	}
}

func TestBundledClientVersions(t *testing.T) {
	root := os.Getenv("NETLAUNCH_TEST_RUNTIME")
	if root == "" {
		t.Skip("set NETLAUNCH_TEST_RUNTIME to check actual bundled executables")
	}
	r, e := Check(context.Background(), root)
	if e != nil || !r.ClientsLoadable {
		t.Fatal(r, e)
	}
}

func TestVersionOutputIsBounded(t *testing.T) {
	var w boundedOutput
	input := []byte(strings.Repeat("x", 100<<10))
	for i := 0; i < 2; i++ {
		if n, e := w.Write(input); n != len(input) || e != nil {
			t.Fatal(n, e)
		}
	}
	if len(w.data) != 16<<10 {
		t.Fatal("unbounded command output")
	}
}
