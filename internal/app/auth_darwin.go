//go:build darwin

package app

import (
	"context"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"

	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
)

func authenticationSupported() bool { return true }
func launchAuthWindow(o options, marker string) (func(), error) {
	self, e := os.Executable()
	if e != nil {
		return nil, e
	}
	script := "#!/bin/sh\n" + quote(self) + " _auth --profile " + quote(o.profile) + " --runtime " + quote(o.runtime) + " --run " + quote(marker) + "\nrc=$?\nprintf '\\nAuthentication finished (exit %s). Press Enter to close.\\n' \"$rc\"\nread answer\nexit \"$rc\"\n"
	entry := filepath.Join(marker, "公司认证.command")
	if e = securefile.Bytes(entry, []byte(script)); e != nil {
		return nil, e
	}
	if e = os.Chmod(entry, 0700); e != nil {
		return nil, e
	}
	if e = exec.Command("/usr/bin/open", "-a", "Terminal", entry).Run(); e != nil {
		return nil, errors.New("could not open local authentication Terminal")
	}
	return func() {}, nil
}
func authenticationCommand(ctx context.Context, root string, vpn policy.VPN) (*exec.Cmd, error) {
	u, e := url.Parse(vpn.Server)
	if e != nil {
		return nil, e
	}
	cmd := exec.CommandContext(ctx, filepath.Join(root, "bin/openconnect"), "--protocol=anyconnect", "--no-proxy", "--no-system-trust", "--cafile=/etc/ssl/cert.pem", "--authenticate", "--resolve="+u.Hostname()+":"+vpn.EndpointIPv4, vpn.Server)
	cmd.Env = append(os.Environ(), "OPENSSL_CONF=/dev/null")
	return cmd, nil
}
func authenticationConsole() (*os.File, *os.File, func(), error) {
	return os.Stdin, os.Stderr, func() {}, nil
}
