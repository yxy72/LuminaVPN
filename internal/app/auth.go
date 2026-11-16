package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"netlaunch/internal/auth"
	"netlaunch/internal/engine"
	"netlaunch/internal/policy"
	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/securefile"
)

func publishDarwinCompanyRefresh(ctx context.Context, run *RunStop, generation uint64, vpn policy.VPN, session any) error {
	if err := run.check(ctx); err != nil {
		return err
	}
	if _, err := run.dir.Lstat("STOP"); !errors.Is(err, os.ErrNotExist) {
		return nil // ordinary cache is still available for the next run
	}
	raw, err := json.Marshal(map[string]any{"generation": generation, "vpn": vpn, "session": session})
	if err != nil {
		return err
	}
	defer clear(raw)
	name := ".auth-refresh-" + rand.Text()
	f, err := run.dir.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer run.dir.Remove(name)
	_, err = f.Write(raw)
	if err := errors.Join(err, f.Sync(), f.Close()); err != nil {
		return err
	}
	if err := run.check(ctx); err != nil {
		return err
	}
	return run.dir.Rename(name, "auth-refresh.json")
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 128<<10 {
		return 0, errors.New("authentication output exceeded limit")
	}
	return b.Buffer.Write(p)
}

const (
	macCompanyAuthPrefix  = "auth-company-"
	macCompanyAuthRequest = "company-vpn.json"
)

// AuthenticateMacCompany refreshes the local company session in the ordinary
// user's Terminal. This does not stage or start network takeover.
func AuthenticateMacCompany(ctx context.Context, profile, bundle string) error {
	return authenticateMacCompany(ctx, profile, bundle, nil, 0)
}

// AuthenticateMacCompany binds the Terminal refresh to exactly the observed
// running generation. The coordinator independently checks its frozen VPN.
func (r *RunStop) AuthenticateMacCompany(ctx context.Context, profile, bundle string, generation uint64) error {
	return authenticateMacCompany(ctx, profile, bundle, r, generation)
}

func (r *RunStop) checkMacCompany(ctx context.Context, generation uint64) error {
	status, err := r.checkMacChannelGeneration(ctx, generation)
	if err != nil {
		return err
	}
	if !status.DarwinCompanyControl {
		return errors.New("selected macOS company channel is unavailable")
	}
	return nil
}

func (r *RunStop) checkMacChannelGeneration(ctx context.Context, generation uint64) (engine.Status, error) {
	if err := r.check(ctx); err != nil {
		return engine.Status{}, err
	}
	if _, err := r.dir.Lstat("STOP"); !errors.Is(err, os.ErrNotExist) {
		return engine.Status{}, errors.New("macOS run is stopping")
	}
	status, err := statusFor(r.path)
	if err != nil || generation == 0 || status.AppliedGeneration != generation ||
		status.ChannelGeneration != generation || !status.TakeoverActive {
		return engine.Status{}, errors.New("selected macOS channel generation is unavailable")
	}
	return status, nil
}

func authenticateMacCompany(ctx context.Context, profile, bundle string, run *RunStop, generation uint64) error {
	if runtime.GOOS != "darwin" || os.Geteuid() == 0 {
		return errors.New("macOS desktop authentication requires the ordinary user")
	}
	if !filepath.IsAbs(profile) || filepath.Clean(profile) != profile ||
		!filepath.IsAbs(bundle) || filepath.Clean(bundle) != bundle {
		return errors.New("local desktop profile or runtime is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := securefile.CheckDir(profile); err != nil {
		return err
	}
	unlock, err := securefile.Lock(filepath.Join(profile, "launch.lock"), time.Second)
	if err != nil {
		return err
	}
	defer unlock()
	if err := requireCompleteConfigTransaction(profile); err != nil {
		return err
	}
	intent := policy.ChannelIntent{Company: true}
	cfg, err := readPolicyForIntent(profile, intent)
	if err != nil {
		return err
	}
	if run != nil {
		if err := run.checkMacCompany(ctx, generation); err != nil {
			return err
		}
		current, err := statusFor(run.path)
		if err != nil || current.AppliedChannels == nil || !current.AppliedChannels.Company {
			return errors.New("selected company channel is no longer enabled")
		}
		frozen, err := engine.ReadManifest(run.path)
		if err != nil || frozen.Mode == "" || frozen.Config.VPN != cfg.VPN {
			return errors.New("configured company endpoint changed since the run started")
		}
	}
	c := CLI{Out: io.Discard, Err: io.Discard}
	if err := c.obtainAuthContext(ctx, options{profile: profile, runtime: bundle, force: true, channels: &intent}, cfg); err != nil || run == nil {
		return err
	}
	if err := run.checkMacCompany(ctx, generation); err != nil {
		return err
	}
	current, err := statusFor(run.path)
	if err != nil || current.AppliedChannels == nil || !current.AppliedChannels.Company {
		return errors.New("selected company channel is no longer enabled")
	}
	session, ok := auth.Load(profile, cfg.VPN)
	if !ok {
		return errors.New("company authentication did not produce a valid session")
	}
	if err := publishDarwinCompanyRefresh(ctx, run, generation, cfg.VPN, session); err != nil {
		return err
	}
	return run.checkMacCompany(ctx, generation)
}

func readAuthenticationPolicy(o options) (policy.Config, error) {
	if runtime.GOOS != "darwin" || !strings.HasPrefix(filepath.Base(o.run), macCompanyAuthPrefix) {
		return readPolicy(o.profile)
	}
	raw, err := securefile.Read(filepath.Join(o.run, macCompanyAuthRequest), 4096, true)
	if err != nil {
		return policy.Config{}, err
	}
	var vpn policy.VPN
	if json.Unmarshal(raw, &vpn) != nil {
		return policy.Config{}, errors.New("invalid company authentication request")
	}
	cfg, err := readPolicyForIntent(o.profile, policy.ChannelIntent{Company: true})
	if err != nil {
		return policy.Config{}, err
	}
	if cfg.VPN != vpn {
		return policy.Config{}, errors.New("company authentication endpoint changed")
	}
	return cfg, nil
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
	prefix := "auth-"
	if runtime.GOOS == "darwin" && o.channels != nil {
		prefix = macCompanyAuthPrefix
	}
	marker, e := securefile.TempDir(o.profile, prefix)
	if e != nil {
		return e
	}
	defer os.RemoveAll(marker)
	if prefix == macCompanyAuthPrefix {
		// The Terminal helper independently validates this exact endpoint
		// against the selected profile before executing OpenConnect.
		if err := securefile.Write(filepath.Join(marker, macCompanyAuthRequest), cfg.VPN); err != nil {
			return err
		}
	}
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
	cfg, e := readAuthenticationPolicy(o)
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
	if !sameAuthRequest(o.run, request) {
		return errors.New("local company authentication request is no longer active")
	}
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
