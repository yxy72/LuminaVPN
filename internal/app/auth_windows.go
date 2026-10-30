//go:build windows

package app

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/winproc"
	"os"
	"os/exec"
	"path/filepath"
)

func authenticationSupported() bool { return true }

func launchAuthWindow(o options, marker string) (func(), error) {
	self, e := os.Executable()
	if e != nil {
		return nil, e
	}
	// Kill-on-close bounds the authentication helper and its OpenConnect child
	// to this request. No credential is passed in an argument or environment.
	job, e := winproc.NewJob()
	if e != nil {
		return nil, e
	}
	p, e := job.Start(winproc.Spec{Args: []string{self, "_auth", "--profile", o.profile, "--runtime", o.runtime, "--run", marker}, NewConsole: true}, func(platform.Identity) error { return releaseAuthentication(marker) })
	if e != nil {
		job.Close()
		return nil, fmt.Errorf("could not open the owned authentication console: %w", e)
	}
	go func() { _, _ = p.Wait() }()
	return func() { _ = job.Close() }, nil
}

func authenticationCommand(ctx context.Context, root string, vpn policy.VPN) (*exec.Cmd, error) {
	u, e := url.Parse(vpn.Server)
	if e != nil {
		return nil, e
	}
	ca := filepath.Join(root, "certs", "ca-bundle.crt")
	if st, e := os.Stat(ca); e != nil || !st.Mode().IsRegular() {
		return nil, errors.New("verified CA bundle is missing")
	}
	cmd := exec.CommandContext(ctx, filepath.Join(root, "bin", "openconnect.exe"), "--protocol=anyconnect", "--no-proxy", "--no-system-trust", "--cafile="+ca, "--authenticate", "--resolve="+u.Hostname()+":"+vpn.EndpointIPv4, vpn.Server)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "OPENSSL_CONF=NUL")
	return cmd, nil
}

func authenticationConsole() (*os.File, *os.File, func(), error) {
	in, e := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if e != nil {
		return nil, nil, nil, e
	}
	out, e := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if e != nil {
		in.Close()
		return nil, nil, nil, e
	}
	return in, out, func() { in.Close(); out.Close() }, nil
}
