package runtimebundle

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type ClientCheck struct {
	Component       string `json:"component"`
	Status          string `json:"status"`
	ExpectedVersion string `json:"expected_version"`
}

type CheckResult struct {
	BundleVerified  bool           `json:"bundle_verified"`
	ClientsLoadable bool           `json:"clients_loadable"`
	NetworkChanges  bool           `json:"network_changes"`
	Checks          []ClientCheck  `json:"checks"`
	Libraries       []LibraryCheck `json:"libraries,omitempty"`
}

type LibraryCheck struct {
	Component string `json:"component"`
	Status    string `json:"status"`
	Scope     string `json:"scope"`
}

// Check executes only version commands after verifying the entire bundle.
// Windows also checks library loading, without calling driver or adapter APIs.
func Check(ctx context.Context, root string) (CheckResult, error) {
	r, e := check(ctx, root, runVersion)
	if e != nil {
		return r, e
	}
	root, e = filepath.Abs(root)
	if e != nil {
		return r, e
	}
	r.Libraries, e = checkLibraries(root)
	return r, e
}

type versionRunner func(context.Context, string, string) (string, error)

func check(ctx context.Context, root string, run versionRunner) (CheckResult, error) {
	r := CheckResult{Checks: []ClientCheck{}}
	root, e := filepath.Abs(root)
	if e != nil {
		return r, errors.New("invalid runtime directory")
	}
	m, e := Verify(root)
	if e != nil {
		return r, e
	}
	r.BundleVerified = true
	if m.Mihomo == "" || m.OpenConnect == "" {
		return r, errors.New("runtime version metadata is missing")
	}
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	for _, client := range []struct{ name, argument, version string }{
		{"mihomo", "-v", m.Mihomo},
		{"openconnect", "--version", m.OpenConnect},
	} {
		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		output, err := run(checkCtx, filepath.Join(root, "bin", client.name+suffix), client.argument)
		status := "pass"
		switch {
		case checkCtx.Err() != nil:
			status = "timeout_or_cancelled"
		case err != nil:
			status = "execution_failed"
		case !matchesVersion(output, client.version):
			status = "version_mismatch"
		}
		cancel()
		r.Checks = append(r.Checks, ClientCheck{client.name, status, client.version})
		if status != "pass" {
			// Do not retry a binary that the operating system may have blocked.
			return r, errors.New(client.name + " runtime check failed: " + status)
		}
	}
	r.ClientsLoadable = true
	return r, nil
}

func matchesVersion(output, expected string) bool {
	for _, token := range strings.Fields(output) {
		if strings.TrimPrefix(token, "v") == strings.TrimPrefix(expected, "v") {
			return true
		}
	}
	return false
}

type boundedOutput struct{ data []byte }

func (w *boundedOutput) Write(b []byte) (int, error) {
	n := len(b)
	if left := (16 << 10) - len(w.data); left > 0 {
		if len(b) > left {
			b = b[:left]
		}
		w.data = append(w.data, b...)
	}
	return n, nil
}

func runVersion(ctx context.Context, executable, argument string) (string, error) {
	cmd := exec.CommandContext(ctx, executable, argument)
	cmd.Dir = filepath.Dir(executable)
	// Avoid inheriting loader injection or personal configuration variables.
	cmd.Env = []string{"OPENSSL_CONF=" + os.DevNull}
	if runtime.GOOS == "windows" {
		for _, key := range []string{"SystemRoot", "WINDIR"} {
			if value := os.Getenv(key); value != "" {
				cmd.Env = append(cmd.Env, key+"="+value)
			}
		}
	}
	var output boundedOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	cmd.WaitDelay = time.Second
	e := cmd.Run()
	return string(output.data), e
}
