package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netlaunch/internal/auth"
	"netlaunch/internal/policy"
	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/securefile"
)

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 128<<10 {
		return 0, errors.New("authentication output exceeded limit")
	}
	return b.Buffer.Write(p)
}
func (c CLI) obtainAuth(o options, cfg policy.Config) error {
	return c.obtainAuthContext(context.Background(), o, cfg)
}

func (c CLI) obtainAuthContext(parent context.Context, o options, cfg policy.Config) error {
	if err := parent.Err(); err != nil {
		return err
	}
	if !authenticationSupported() {
		return errors.New("local VPN authentication is not available on this platform")
	}
	if !o.force {
		if _, ok := auth.Load(o.profile, cfg.VPN); ok {
			fmt.Fprintln(c.Out, "Reusing a local VPN session (maximum age: 2 hours).")
			return nil
		}
	}
	if _, e := runtimebundle.Verify(o.runtime); e != nil {
		return e
	}
	if e := securefile.Dir(o.profile); e != nil {
		return e
	}
	unlock, e := securefile.Lock(filepath.Join(o.profile, "auth-request.lock"), time.Second)
	if e != nil {
		return e
	}
	defer unlock()
	// Another request may have completed while this caller waited for the lock.
	if !o.force {
		if _, ok := auth.Load(o.profile, cfg.VPN); ok {
			fmt.Fprintln(c.Out, "Reusing a local VPN session (maximum age: 2 hours).")
			return nil
		}
	}
	// A unique marker avoids treating a previous terminal's result as this request's result.
	marker, e := securefile.TempDir(o.profile, "auth-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(marker)
	if e := parent.Err(); e != nil {
		return e
	}
	fmt.Fprintln(c.Out, "Complete company authentication in the local Terminal window. Passwords and one-time codes are never saved.")
	cleanup, e := launchAuthWindow(o, marker)
	if e != nil {
		return e
	}
	defer cleanup()
	wait, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		if wait.Err() != nil {
			if parent.Err() != nil {
				return parent.Err()
			}
			return errors.New("local authentication timed out; close its Terminal window before retrying")
		}
		if _, e := os.Stat(filepath.Join(marker, "done")); e == nil {
			if _, ok := auth.Load(o.profile, cfg.VPN); ok {
				return nil
			}
			return errors.New("authentication completed but no valid session was saved")
		}
		if _, e := os.Stat(filepath.Join(marker, "failed")); e == nil {
			return errors.New("local company authentication did not complete")
		}
		select {
		case <-wait.Done():
		case <-tick.C:
		}
	}
}
func (c CLI) authenticate(o options) (returned error) {
	if !authenticationSupported() {
		return errors.New("local VPN authentication is not available on this platform")
	}
	// Only a private marker created by this profile may receive completion events.
	if filepath.Dir(o.run) != o.profile || !strings.HasPrefix(filepath.Base(o.run), "auth-") {
		return errors.New("invalid authentication request")
	}
	if e := securefile.CheckDir(o.run); e != nil {
		return e
	}
	request, e := os.Lstat(o.run)
	if e != nil {
		return e
	}
	if e := awaitAuthentication(o.run); e != nil {
		return e
	}
	defer func() {
		name := "done"
		if returned != nil {
			name = "failed"
		}
		// This marker directory belongs to the request. A late helper must
		// not recreate it after the caller has retired the request.
		_ = writeAuthReceipt(o.run, request, name)
	}()
	cfg, e := readPolicy(o.profile)
	if e != nil {
		return e
	}
	if _, e = runtimebundle.Verify(o.runtime); e != nil {
		return e
	}
	unlock, e := securefile.Lock(filepath.Join(o.profile, "auth.lock"), time.Second)
	if e != nil {
		return e
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	go watchAuthRequest(ctx, cancel, o.run, request)
	cmd, e := authenticationCommand(ctx, o.runtime, cfg.VPN)
	if e != nil {
		return e
	}
	in, out, closeConsole, e := authenticationConsole()
	if e != nil {
		return e
	}
	defer closeConsole()
	var output limitedBuffer
	cmd.Stdin = in
	cmd.Stderr = out
	cmd.Stdout = &output
	if e = cmd.Run(); e != nil {
		return errors.New("company authentication was cancelled or rejected")
	}
	session, e := auth.Parse(output.String(), cfg.VPN)
	output.Reset()
	if e != nil {
		return e
	}
	if e := ctx.Err(); e != nil || !sameAuthRequest(o.run, request) {
		return errors.New("local company authentication request is no longer active")
	}
	if e = auth.Save(o.profile, cfg.VPN, session); e != nil {
		return e
	}
	fmt.Fprintln(out, "认证完成。仅缓存 VPN 会话，最多复用两小时；未保存密码或动态码。")
	return nil
}

func sameAuthRequest(path string, expected os.FileInfo) bool {
	current, err := os.Lstat(path)
	return err == nil && current.IsDir() && os.SameFile(expected, current)
}

func watchAuthRequest(ctx context.Context, cancel context.CancelFunc, path string, expected os.FileInfo) {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for sameAuthRequest(path, expected) {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
	cancel()
}

func writeAuthReceipt(path string, expected os.FileInfo, name string) error {
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	identity, err := root.Stat(".")
	if err != nil || !os.SameFile(expected, identity) {
		return errors.New("local company authentication request changed")
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	return f.Close()
}
