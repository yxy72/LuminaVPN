//go:build darwin || windows

package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"netlaunch/internal/personalroute"
	"netlaunch/internal/policy"
	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/securefile"
)

// MeasureDesktopLatency launches an isolated core with only a loopback
// controller. It does not start TUN, a proxy listener, DNS, or a native run.
func MeasureDesktopLatency(ctx context.Context, bundle, profile string, nodes []policy.Node, target string) (map[string]int, error) {
	if _, err := runtimebundle.Verify(bundle); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(profile, ".node-probe-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	controller := listener.Addr().String()
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		listener.Close()
		return nil, err
	}
	key := hex.EncodeToString(secret)
	config := map[string]any{
		"external-controller": controller, "secret": key, "allow-lan": false,
		"mode": "rule", "log-level": "silent", "ipv6": false,
		"tun": map[string]bool{"enable": false}, "dns": map[string]bool{"enable": false},
		"proxies": nodes, "rules": []string{"MATCH,REJECT"},
	}
	path := filepath.Join(dir, "probe.json")
	err = securefile.Write(path, config)
	listener.Close()
	if err != nil {
		return nil, err
	}
	image := "mihomo"
	if runtime.GOOS == "windows" {
		image += ".exe"
	}
	child := exec.CommandContext(ctx, filepath.Join(bundle, "bin", image), "-d", dir, "-f", path)
	hideDesktopProbe(child)
	if err = child.Start(); err != nil {
		return nil, err
	}
	defer func() { child.Process.Kill(); child.Wait() }()

	request := func(ctx context.Context, path string, result any) error {
		return coreRequest(ctx, controller, key, "GET", path, nil, result)
	}
	ready, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	for {
		check, done := context.WithTimeout(ready, 300*time.Millisecond)
		var identity struct{ Version string }
		err = request(check, "/version", &identity)
		done()
		if err == nil && identity.Version != "" {
			break
		}
		select {
		case <-ready.Done():
			return nil, errors.New("isolated node controller unavailable")
		case <-time.After(60 * time.Millisecond):
		}
	}
	values := sampleNodes(ctx, candidateNames(nodes), 50*time.Second, 16, func(ctx context.Context, node string) (int, bool) {
		sample := independentNode(ctx, node, "", "", personalroute.Generation{}, []string{target}, request)
		switch sample.Observation.Outcome {
		case personalroute.Healthy:
			return sample.Latency, true
		case personalroute.PathFailed:
			return -1, true
		default:
			return 0, false
		}
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return values, nil
}
