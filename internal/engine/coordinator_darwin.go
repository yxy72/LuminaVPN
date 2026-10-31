//go:build darwin

package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"netlaunch/internal/auth"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/securefile"
	"netlaunch/internal/selector"
)

func copyExecutable(from, to string) error {
	in, e := os.Open(from)
	if e != nil {
		return e
	}
	defer in.Close()
	out, e := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if e != nil {
		return e
	}
	_, e = io.Copy(out, in)
	ce := out.Close()
	if e != nil {
		return e
	}
	return ce
}
func initialize(run string) (State, error) {
	m, e := ReadManifest(run)
	if e != nil {
		return State{}, e
	}
	if _, e = os.Lstat(private(run)); !errors.Is(e, os.ErrNotExist) {
		return State{}, errors.New("run already used")
	}
	if e = securefile.Dir(filepath.Dir(private(run))); e != nil {
		return State{}, e
	}
	if e = os.Mkdir(private(run), 0700); e != nil {
		return State{}, e
	}
	self, e := os.Executable()
	if e != nil {
		return State{}, e
	}
	identity, e := platform.Process(os.Getpid())
	if e != nil || identity.PID == 0 {
		return State{}, errors.New("coordinator identity unavailable")
	}
	m.Executable = filepath.Join(private(run), "netlaunch")
	s := State{Version: 1, Phase: "preparing", Heartbeat: time.Now(), Runner: identity, Manifest: m, DNS: map[string]DNSChange{}, Personal: selector.Reject}
	if e = initializeStateStorage(run, &s); e != nil {
		return s, e
	}
	if e = save(run, &s); e != nil {
		return s, e
	}
	if e = copyExecutable(self, m.Executable); e != nil {
		return s, e
	}
	return s, nil
}
func serve(run string) (returned error) {
	if _, e := ReadManifest(run); e != nil {
		return e
	}
	if e := securefile.Dir(filepath.Dir(private(run))); e != nil {
		return e
	}
	// Only one coordinator may own native mutations across all user profiles.
	unlock, e := securefile.Lock(filepath.Join(filepath.Dir(private(run)), "active.lock"), time.Second)
	if e != nil {
		return errors.New("another native coordinator is active")
	}
	defer unlock()
	s, e := initialize(run)
	if e != nil {
		if validateRoot(run) == nil {
			_ = recoverRun(run, "initialization_failed")
		}
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	defer func() {
		cancel()
		reason := "coordinator_exit"
		if errors.Is(returned, errVPNAuthenticationRequired) {
			reason = "authentication_required"
		}
		if returned != nil {
			_ = update(run, func(s *State) error { s.Error = runtimeFailureReason(returned); return nil })
		}
		_ = recoverRun(run, reason)
	}()
	// Freeze the executables and secrets in root-owned storage before executing them.
	if e = runtimebundle.Copy(filepath.Join(run, "runtime"), filepath.Join(private(run), "runtime")); e != nil {
		return e
	}
	var nodes []policy.Node
	if e = readJSON(filepath.Join(run, "nodes.json"), &nodes); e != nil {
		return e
	}
	nodes, e = policy.SanitizeNodes(nodes)
	if e != nil {
		return e
	}
	session, e := readAuth(run)
	if e != nil {
		return e
	}
	if e = securefile.Write(filepath.Join(private(run), "auth.json"), session); e != nil {
		return e
	}
	_ = os.Remove(filepath.Join(run, "auth.json"))
	if e = securefile.Write(filepath.Join(private(run), "nodes.json"), nodes); e != nil {
		return e
	}
	_ = os.Remove(filepath.Join(run, "nodes.json"))
	network, e := platform.Discover()
	if e != nil || network != s.Manifest.Network {
		return errors.New("network changed during authorization; prepare a new run")
	}
	if platform.ForeignVPN() {
		return errors.New("another OpenConnect process is active")
	}
	if e = platform.CheckConflicts(network); e != nil {
		return e
	}
	for _, port := range []int{s.Manifest.Config.Ports.Proxy, s.Manifest.Config.Ports.DNS, s.Manifest.Binding.ControllerPort} {
		if e := platform.CheckPort(port); e != nil {
			return e
		}
	}
	interfaces, e := platform.Interfaces()
	if e != nil {
		return e
	}
	if interfaces[s.Manifest.Binding.VPN] || interfaces[s.Manifest.Binding.TUN] {
		return errors.New("candidate interface now in use")
	}
	secretBytes := make([]byte, 32)
	if _, e = rand.Read(secretBytes); e != nil {
		return e
	}
	secret := hex.EncodeToString(secretBytes)
	config, e := policy.Compile(s.Manifest.Config, nodes, s.Manifest.Binding, secret)
	if e != nil {
		return e
	}
	company, e := startCompany(ctx, run)
	if e != nil {
		return e
	}
	if e = company.configure(config); e != nil {
		return e
	}
	if e = saveCore(run, config); e != nil {
		return e
	}
	core := filepath.Join(private(run), "runtime/bin/mihomo")
	if e = native(ctx, core, "-t", "-d", private(run), "-f", filepath.Join(private(run), "core.json")); e != nil {
		return errors.New("generated core configuration rejected")
	}
	watchLog, e := os.OpenFile(filepath.Join(private(run), "watchdog-private.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		return e
	}
	watcher := exec.Command(s.Manifest.Executable, "_watch", "--run", run)
	watcher.Stdout = watchLog
	watcher.Stderr = watchLog
	watcher.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	e = watcher.Start()
	watchLog.Close()
	if e != nil {
		return errors.New("independent watchdog could not start")
	}
	go func() { _ = watcher.Wait() }()
	id, e := platform.Process(watcher.Process.Pid)
	if e != nil || id.PID == 0 {
		return errors.New("watchdog identity unavailable")
	}
	if e = update(run, func(s *State) error { s.Watcher = id; return nil }); e != nil {
		return e
	}
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if alivePulse(run) != nil {
					cancel()
					return
				}
			}
		}
	}()
	if e = endpoint(run, network); e != nil {
		return e
	}
	exits := &childExitTracker{}
	vpnChild, e := startVPN(run, exits)
	if e != nil {
		return e
	}
	if e = wait(ctx, run, 45*time.Second, func(ctx context.Context) error {
		if live, err := alive(vpnChild); err != nil || !live {
			return &terminalReadinessError{vpnBootstrapFailure(run, vpnChild)}
		}
		s, e := load(run)
		if e != nil {
			return e
		}
		if !s.VPN.Bootstrap || !validVPN(s) {
			return vpnBootstrapFailure(run, vpnChild)
		}
		return company.ready()
	}); e != nil {
		return e
	}
	coreChild, e := spawn(run, "core", []string{core, "-d", private(run), "-f", filepath.Join(private(run), "core.json")}, exits)
	if e != nil {
		return e
	}
	if e = wait(ctx, run, 10*time.Second, func(ctx context.Context) error {
		ok, e := alive(coreChild)
		if e != nil {
			return e
		}
		if !ok {
			return errors.New("core exited")
		}
		return apiContext(ctx, run, "GET", "/configs", nil, &map[string]any{})
	}); e != nil {
		return e
	}
	if e = openCompany(ctx, run, company); e != nil {
		return e
	}
	names := []string{}
	for _, n := range nodes {
		names = append(names, n["name"].(string))
	}
	selection := selector.New(names)
	if e = wait(ctx, run, 45*time.Second, func(ctx context.Context) error {
		if e := choose(ctx, run, selection); e != nil {
			return e
		}
		if selection.Current == selector.Reject {
			return errors.New("no healthy personal node")
		}
		return nil
	}); e != nil {
		return e
	}
	if e = apiContext(ctx, run, "PATCH", "/configs", map[string]any{"tun": map[string]bool{"enable": true}}, nil); e != nil {
		return e
	}
	if e = wait(ctx, run, 8*time.Second, func(ctx context.Context) error {
		i, e := platform.Interfaces()
		if e != nil {
			return e
		}
		if !i[s.Manifest.Binding.TUN] {
			return errors.New("candidate TUN is not ready")
		}
		return nil
	}); e != nil {
		return e
	}
	if e = takeoverDNS(run); e != nil {
		return e
	}
	if e = wait(ctx, run, 60*time.Second, func(ctx context.Context) error {
		if e := ensurePersonalSelection(ctx, run, selection); e != nil {
			return e
		}
		if e := openCompany(ctx, run, company); e != nil {
			return e
		}
		ready, err := checkSystemChannels(ctx, run, s.Manifest.Config.Probes, selection, company.ready() == nil, false)
		if err != nil {
			return err
		}
		if !ready {
			// Preserve the native startup retry's DNS cache refresh.
			_ = apiContext(ctx, run, "POST", "/cache/dns/flush", nil, nil)
			if ctx.Err() == nil {
				platform.FlushDNS()
			}
			return errors.New("system channel verification failed")
		}
		return nil
	}); e != nil {
		return e
	}
	if e = update(run, func(s *State) error { s.Phase = "ready"; s.LastReady = time.Now(); s.Error = ""; return nil }); e != nil {
		return e
	}
	sampling := &personalSampling{}
	defer sampling.close()
	lastHealth, lastProbe := time.Now(), time.Now()
	lastGeneration := ""
	lastResumeRequest := ""
	retry := &vpnRetry{}
	disconnected := false
	networkUnavailable := false
	for ctx.Err() == nil {
		select {
		case <-company.done:
			return errors.New("company ingress stopped")
		default:
		}
		if e = pulse(run); e != nil {
			return nil
		}
		current, e := load(run)
		if e != nil {
			return e
		}
		epoch, e := platform.WakeEpoch()
		if e != nil {
			return e
		}
		if current.VPN.WakeEpoch != "" && current.VPN.WakeEpoch != epoch && lastResumeRequest != epoch {
			company.revoke()
			if e = gate(run); e != nil {
				return e
			}
			if e = selectPersonal(run, selector.Reject); e != nil {
				return e
			}
			if e = update(run, func(s *State) error { s.VPN.Bootstrap = false; s.Leases = nil; s.Phase = "reconnecting"; return nil }); e != nil {
				return e
			}
			for _, child := range current.Children {
				if child.Role != "vpn" {
					continue
				}
				alive, e := alive(child)
				if e != nil {
					return e
				}
				if alive {
					if e = syscall.Kill(child.PID, syscall.SIGUSR2); e != nil {
						return e
					}
				}
			}
			lastResumeRequest = epoch
			retry.NetworkChanged(time.Now())
			selection = selector.New(names)
			lastHealth, lastProbe = time.Time{}, time.Time{}
			continue
		}
		ok, e := alive(coreChild)
		if e != nil || !ok {
			return errors.New("owned core disappeared")
		}
		observed, e := platform.Discover()
		if e != nil {
			networkUnavailable = true
			company.revoke()
			_ = gate(run)
			_ = update(run, func(s *State) error {
				s.VPN.Bootstrap = false
				s.Leases = nil
				s.Phase = "network_unavailable"
				return nil
			})
			time.Sleep(time.Second)
			continue
		}
		if observed != network || networkUnavailable {
			company.revoke()
			_ = gate(run)
			_ = selectPersonal(run, selector.Reject)
			if e = update(run, func(s *State) error { s.VPN.Bootstrap = false; s.Leases = nil; return nil }); e != nil {
				return e
			}
			if e = endpoint(run, observed); e != nil {
				return e
			}
			binding := current.Manifest.Binding
			binding.Physical = observed.Interface
			config, e = policy.Compile(current.Manifest.Config, nodes, binding, secret)
			if e != nil {
				return e
			}
			if e = company.configure(config); e != nil {
				return e
			}
			config["tun"].(map[string]any)["enable"] = true
			if e = saveCore(run, config); e != nil {
				return e
			}
			if e = apiContext(ctx, run, "PUT", "/configs?force=true", map[string]string{"path": filepath.Join(private(run), "core.json")}, nil); e != nil {
				return e
			}
			if e = update(run, func(s *State) error {
				s.Manifest.Network = observed
				s.Manifest.Binding = binding
				s.Phase = "reconnecting"
				return nil
			}); e != nil {
				return e
			}
			if e = takeoverDNS(run); e != nil {
				return e
			}
			network = observed
			networkUnavailable = false
			retry.NetworkChanged(time.Now())
			selection = selector.New(names)
			lastHealth = time.Time{}
			for _, c := range current.Children {
				if c.Role == "vpn" {
					if ok, _ := alive(c); ok {
						_ = syscall.Kill(c.PID, syscall.SIGUSR2)
					}
				}
			}
		}
		current, e = load(run)
		if e != nil {
			return e
		}
		if _, e := os.Stat(filepath.Join(run, "auth-refresh.json")); e == nil {
			var fresh auth.Session
			if e = readJSON(filepath.Join(run, "auth-refresh.json"), &fresh); e != nil || requireVPNAuthentication(fresh, current.Manifest.Config.VPN, time.Now()) != nil {
				return errors.New("invalid refreshed authentication")
			}
			if e = stopVPN(run, company); e != nil {
				return e
			}
			disconnected = true
			if e = securefile.Write(filepath.Join(private(run), "auth.json"), fresh); e != nil {
				return e
			}
			if e = os.Remove(filepath.Join(run, "auth-refresh.json")); e != nil {
				return e
			}
			retry.FreshAuthentication(time.Now())
			delete(exits.exits, "vpn")
		}
		vpnAlive := false
		currentVPN, hasVPN := latestVPN(current)
		if hasVPN {
			vpnAlive, e = alive(currentVPN)
			if e != nil {
				return e
			}
		}
		exitKnown := false
		if !vpnAlive && hasVPN {
			if reason, known := exits.failure(currentVPN); known {
				exitKnown = true
				if e = retry.Failed(time.Now(), currentVPN, reason); e != nil {
					return e
				}
			}
		}
		if !vpnAlive && !disconnected {
			if e = stopVPN(run, company); e != nil {
				return e
			}
			disconnected = true
		}
		if (!vpnAlive || retry.AuthenticationRequired) && current.Phase != vpnRecoveryPhase(retry) {
			if e = update(run, func(s *State) error { markVPNRecovery(s, retry); return nil }); e != nil {
				return e
			}
		}
		if !vpnAlive && (exitKnown || exits.exits["vpn"] == nil) && retry.Due(time.Now()) {
			if _, e = startVPN(run, exits); e != nil {
				if !errors.Is(e, errVPNAuthenticationRequired) {
					return e
				}
				retry.AuthenticationRequired = true
				if e = update(run, func(s *State) error { markVPNRecovery(s, retry); return nil }); e != nil {
					return e
				}
			} else {
				retry.Attempted(time.Now())
				disconnected = false
			}
			continue // reload the newly journalled attempt and its generation
		}
		retry.Ready(time.Now(), vpnAlive && company.ready() == nil)
		refresh := current.VPN.Generation != lastGeneration || channelView(current, "company", time.Now()).State != "ready" || company.ready() != nil
		for _, a := range current.Leases {
			if time.Until(a.ExpiresAt) < 15*time.Second {
				refresh = true
			}
		}
		if vpnAlive && !retry.AuthenticationRequired && refresh {
			if e = openCompany(ctx, run, company); e != nil {
				_ = gate(run)
				_ = update(run, func(s *State) error { s.Phase = "company_unavailable"; return nil })
			} else {
				lastGeneration = current.VPN.Generation
				lastProbe = time.Time{}
			}
		}
		if time.Since(lastHealth) > 15*time.Second {
			done, err := sampling.refresh(ctx, run, selection)
			if err != nil {
				return err
			}
			if done {
				lastHealth = time.Now()
			}
		}
		if time.Since(lastProbe) > 30*time.Second {
			ready, err := checkSystemChannels(ctx, run, current.Manifest.Config.Probes, selection, company.ready() == nil, retry.AuthenticationRequired || !vpnAlive)
			if err != nil {
				return err
			}
			if selection.Current == selector.Reject {
				lastHealth = time.Time{}
			}
			_ = update(run, func(s *State) error {
				if ready {
					s.Phase = "ready"
					s.LastReady = time.Now()
					s.Error = ""
				} else if s.Phase != "authentication_required" && s.Phase != "reconnecting" {
					s.Phase = "degraded"
				}
				return nil
			})
			lastProbe = time.Now()
		}
		time.Sleep(time.Second)
	}
	return nil
}

func startVPN(run string, exits *childExitTracker) (Child, error) {
	s, e := load(run)
	if e != nil {
		return Child{}, e
	}
	var a auth.Session
	if e = readJSON(filepath.Join(private(run), "auth.json"), &a); e != nil {
		return Child{}, e
	}
	if e = requireVPNAuthentication(a, s.Manifest.Config.VPN, time.Now()); e != nil {
		return Child{}, e
	}
	u, _ := url.Parse(s.Manifest.Config.VPN.Server)
	hookPath := filepath.Join(private(run), "vpn-hook")
	script := "#!/bin/sh\nexec " + shellQuote(s.Manifest.Executable) + " _hook --run " + shellQuote(run) + "\n"
	if e = securefile.Bytes(hookPath, []byte(script)); e != nil {
		return Child{}, e
	}
	if e = os.Chmod(hookPath, 0700); e != nil {
		return Child{}, e
	}
	args := []string{filepath.Join(private(run), "runtime/bin/openconnect"), "--protocol=anyconnect", "--no-proxy", "--no-system-trust", "--cafile=/etc/ssl/cert.pem", "--non-inter", "--cookie-on-stdin", "--servercert=" + a.Fingerprint, "--resolve=" + u.Hostname() + ":" + s.Manifest.Config.VPN.EndpointIPv4, "--interface=" + s.Manifest.Binding.VPN, vpnScriptOption(hookPath), s.Manifest.Config.VPN.Server}
	return spawn(run, "vpn", args, exits)
}

func stopVPN(run string, company *companyRuntime) error {
	company.revoke()
	if e := gate(run); e != nil {
		return e
	}
	if e := update(run, func(s *State) error { s.VPN.Bootstrap = false; s.Leases = nil; return nil }); e != nil {
		return e
	}
	s, e := load(run)
	if e != nil {
		return e
	}
	for _, c := range s.Children {
		if c.Role == "vpn" {
			if e := stopChild(c); e != nil {
				return e
			}
		}
	}
	return update(run, func(s *State) error {
		if e := guard(run, s); e != nil {
			return e
		}
		for i, route := range s.Routes {
			if route.Route.Scoped && route.State != "removed" {
				if e := removeRoute(run, s, i); e != nil {
					return e
				}
			}
		}
		return nil
	})
}

func vpnScriptOption(path string) string {
	// OpenConnect executes --script as /bin/sh -c, even when OpenConnect
	// itself is launched with an argv array. Application Support contains spaces.
	return "--script=" + shellQuote(path)
}
func watch(run string) error {
	lastEpoch, e := platform.WakeEpoch()
	if e != nil {
		return e
	}
	var resumeGrace time.Time
	for {
		s, e := load(run)
		if e != nil {
			return e
		}
		if s.Phase == "stopped" || s.Phase == "recovery_failed" {
			return nil
		}
		reason := ""
		if _, e = os.Stat(filepath.Join(run, "STOP")); e == nil {
			reason = "user_stop"
		}
		id, _ := platform.Process(s.Runner.PID)
		if id.PID == 0 || id.Birth != s.Runner.Birth || id.Command != s.Runner.Command {
			reason = "coordinator_exited"
		}
		epoch, e := platform.WakeEpoch()
		if e != nil {
			return recoverRun(run, "wake_identity_unavailable")
		}
		if epoch != lastEpoch {
			lastEpoch = epoch
			resumeGrace = time.Now().Add(35 * time.Second)
		}
		if reason == "" && !time.Now().Before(resumeGrace) {
			monitor, err := readMonitor(run, s)
			if err != nil {
				reason = "coordinator_monitor_invalid"
			} else {
				reason = monitorFailure(s, monitor, time.Now())
			}
		}
		if reason != "" {
			return recoverRun(run, reason)
		}
		if leaseExpired(s) {
			e = update(run, func(s *State) error {
				if !leaseExpired(*s) {
					return nil
				}
				if e := gate(run); e != nil {
					return e
				}
				wanted := map[string]bool{}
				for _, d := range s.Manifest.Config.Company.DNS {
					wanted[d+"/32"] = true
				}
				for _, cidr := range s.Manifest.Config.Company.CIDRs {
					wanted[cidr] = true
				}
				valid := s.Leases[:0]
				for _, a := range s.Leases {
					if time.Now().Before(a.ExpiresAt) {
						valid = append(valid, a)
						wanted[a.IP+"/32"] = true
					}
				}
				s.Leases = valid
				for i, r := range s.Routes {
					if r.Route.Scoped && r.State != "removed" && !wanted[r.Route.Prefix] {
						if e := removeRoute(run, s, i); e != nil {
							return e
						}
					}
				}
				s.Phase = "company_unavailable"
				return nil
			})
			if e != nil {
				return recoverRun(run, "lease_guard_failed")
			}
		}
		time.Sleep(time.Second)
	}
}

func recoverRun(run, reason string) error {
	// STOP is also honored if authorization was cancelled before initialization.
	if e := ValidateRun(run); e != nil {
		return e
	}
	if e := securefile.Bytes(filepath.Join(run, "STOP"), nil); e != nil {
		return e
	}
	if _, err := os.Lstat(filepath.Join(private(run), "state.json")); errors.Is(err, os.ErrNotExist) {
		// No networking is possible before the root journal has been created.
		m, e := ReadManifest(run)
		if e != nil {
			return e
		}
		status := Status{Phase: "stopped", Updated: time.Now(), Company: "unavailable", Personal: selector.Reject, RecoveryReason: "cancelled_before_network_changes", Experimental: true}
		p := filepath.Join(run, "status.json")
		if e = securefile.Write(p, status); e != nil {
			return e
		}
		for _, name := range []string{"auth.json", "auth-refresh.json", "nodes.json"} {
			_ = os.Remove(filepath.Join(run, name))
		}
		return os.Chown(p, m.Owner, -1)
	}
	if e := validateRoot(run); e != nil {
		return e
	}
	if e := securefile.Bytes(filepath.Join(run, "STOP"), nil); e != nil {
		return e
	}
	unlock, e := securefile.Lock(filepath.Join(private(run), "recovery.lock"), 180*time.Second)
	if e != nil {
		return e
	}
	defer unlock()
	s, e := load(run)
	if e != nil {
		return e
	}
	if s.Phase == "stopped" {
		return nil
	}
	// A stalled coordinator can hold state.lock. The durable STOP marker and
	// exclusive recovery lock authorize only its recorded identity to be stopped.
	if e = stopCoordinator(s.Runner); e != nil {
		return e
	}
	if e = update(run, func(s *State) error { s.Phase = "stopping"; s.RecoveryReason = reason; return nil }); e != nil {
		return e
	}
	fail := func(e error) error {
		_ = update(run, func(s *State) error {
			s.Phase = "recovery_failed"
			s.Error = "restore_incomplete_run_down_again"
			return nil
		})
		return e
	}
	// Include any child publication completed between the initial read and
	// coordinator termination before recovering the native resources.
	s, e = load(run)
	if e != nil {
		return fail(e)
	}
	_ = gate(run)
	for _, role := range []string{"core", "vpn"} {
		for _, c := range s.Children {
			if c.Role == role {
				if e = stopChild(c); e != nil {
					return fail(e)
				}
			}
		}
	}
	interfaces, e := platform.Interfaces()
	if e != nil {
		return fail(e)
	}
	if interfaces[s.Manifest.Binding.VPN] || interfaces[s.Manifest.Binding.TUN] {
		return fail(errors.New("candidate interface remains; recovery stopped"))
	}
	e = update(run, func(s *State) error {
		for i := len(s.Routes) - 1; i >= 0; i-- {
			if e := removeRoute(run, s, i); e != nil {
				return e
			}
		}
		for service, change := range s.DNS {
			current, e := platform.DNS(service)
			if e != nil {
				return e
			}
			restore, e := restoreDNS(current, change)
			if e != nil {
				return e
			}
			if !restore {
				continue
			}
			before := strings.Join(change.Before, ",")
			if e = platform.SetDNS(service, change.Before); e != nil {
				return e
			}
			current, e = platform.DNS(service)
			if e != nil || strings.Join(current, ",") != before {
				return errors.New("original DNS restoration not verified")
			}
		}
		platform.FlushDNS()
		s.Phase = "stopped"
		s.Personal = selector.Reject
		s.Error = ""
		return nil
	})
	if e != nil {
		return fail(e)
	}
	for _, name := range []string{"auth.json", "nodes.json", "core.json"} {
		_ = os.Remove(filepath.Join(private(run), name))
		_ = os.Remove(filepath.Join(run, name))
	}
	return nil
}

// VerifyOwnedInterfaces is deliberately independent of the status file.
func VerifyOwnedInterfaces(run string) error {
	s, e := load(run)
	if e != nil {
		return e
	}
	for _, n := range []string{s.Manifest.Binding.VPN, s.Manifest.Binding.TUN} {
		if _, e := net.InterfaceByName(n); e == nil {
			return errors.New("candidate interface is still present")
		}
	}
	return nil
}
