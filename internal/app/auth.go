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
	fmt.Fprintln(c.Out, "Complete company authentication in the local Terminal window. Passwords and one-time codes are never saved.")
	cleanup, e := launchAuthWindow(o, marker)
	if e != nil {
		return e
	}
	defer cleanup()
	for i := 0; i < 300; i++ {
		if _, e := os.Stat(filepath.Join(marker, "done")); e == nil {
			if _, ok := auth.Load(o.profile, cfg.VPN); ok {
				return nil
			}
			return errors.New("authentication completed but no valid session was saved")
		}
		if _, e := os.Stat(filepath.Join(marker, "failed")); e == nil {
			return errors.New("local company authentication did not complete")
		}
		time.Sleep(time.Second)
	}
	return errors.New("local authentication timed out; close its Terminal window before retrying")
}
func (c CLI) authenticate(o options) (returned error) {
	if !authenticationSupported() {
		return errors.New("local VPN authentication is not available on this platform")
	}
	// Only a private marker created by this profile may receive completion events.
	if filepath.Dir(o.run) != o.profile || !strings.HasPrefix(filepath.Base(o.run), "auth-") {
		return errors.New("invalid authentication request")
	}
	if e := securefile.Dir(o.run); e != nil {
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
		_ = securefile.Bytes(filepath.Join(o.run, name), nil)
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
	if e = auth.Save(o.profile, cfg.VPN, session); e != nil {
		return e
	}
	fmt.Fprintln(out, "认证完成。仅缓存 VPN 会话，最多复用两小时；未保存密码或动态码。")
	return nil
}
