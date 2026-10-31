//go:build windows

package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"netlaunch/internal/dnsloopback"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"netlaunch/internal/auth"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/securefile"
	"netlaunch/internal/selector"
	"netlaunch/internal/winnet"
	"netlaunch/internal/winproc"
	"netlaunch/internal/winstate"
)

func nonce() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func initialize(run string) (State, error) {
	m, e := ReadManifest(run)
	if e != nil {
		return State{}, e
	}
	if windowsFlowIsolationReady && m.ValidationTimeout == 0 {
		return State{}, errors.New("Windows validation manifest has no hard deadline")
	}
	files, id, e := winFiles(run)
	if e != nil {
		return State{}, e
	}
	if _, e = os.Lstat(private(run)); !errors.Is(e, os.ErrNotExist) {
		return State{}, errors.New("administrator run already exists")
	}
	if e = files.Dir(id); e != nil {
		return State{}, e
	}
	boot, e := winnet.BootID()
	if e != nil {
		return State{}, e
	}
	physical, e := winnet.Discover()
	if e != nil {
		return State{}, e
	}
	if physical.Adapter.Name != m.Network.Interface || physical.Adapter.GUID != m.Network.Service || physical.Address != m.Network.Address || physical.Gateway != m.Network.Gateway {
		return State{}, errors.New("physical network changed during authorization")
	}
	all, e := winnet.Adapters()
	if e != nil {
		return State{}, e
	}
	before := []string{}
	for _, a := range all {
		if a.Name == m.Binding.VPN || a.Name == m.Binding.TUN {
			return State{}, errors.New("candidate interface already exists")
		}
		before = append(before, a.GUID)
	}
	runner, e := platform.Process(os.Getpid())
	if e != nil {
		return State{}, e
	}
	m.Executable = frozenSelf(run)
	s := State{Version: 1, Manifest: m, Runner: runner, Phase: "preparing", Heartbeat: time.Now(), Personal: selector.Reject, Windows: &WindowsState{BootID: boot, PublicRun: run, Physical: physical, AdapterBefore: before}}
	if e = save(run, &s); e != nil {
		return s, e
	}
	if e = files.Write("active.json", map[string]string{"run": run}); e != nil {
		return s, e
	}
	if e = files.Write(filepath.Join(id, "network.json"), winstate.Journal{Version: 1, BootID: boot}); e != nil {
		return s, e
	}
	self, e := os.Executable()
	if e != nil {
		return s, e
	}
	binary, e := securefile.Read(self, 128<<20, true)
	if e != nil {
		return s, e
	}
	if e = files.Bytes(filepath.Join(id, "netlaunch.exe"), binary); e != nil {
		return s, e
	}
	return s, nil
}
func freezeRuntime(run string) error {
	files, id, e := winFiles(run)
	if e != nil {
		return e
	}
	source := filepath.Join(run, "runtime")
	manifest, e := runtimebundle.Verify(source)
	if e != nil {
		return e
	}
	for _, entry := range manifest.Files {
		relative := filepath.Join(id, "runtime", filepath.FromSlash(entry.Path))
		if e = files.Dir(filepath.Dir(relative)); e != nil {
			return e
		}
		b, e := securefile.Read(filepath.Join(source, filepath.FromSlash(entry.Path)), 256<<20, true)
		if e != nil {
			return e
		}
		if e = files.Bytes(relative, b); e != nil {
			return e
		}
	}
	if e = files.Write(filepath.Join(id, "runtime", "manifest.json"), manifest); e != nil {
		return e
	}
	_, e = runtimebundle.Verify(filepath.Join(private(run), "runtime"))
	return e
}
func privateLog(run, name string) (*os.File, error) {
	files, id, e := winFiles(run)
	if e != nil {
		return nil, e
	}
	relative := filepath.Join(id, name+"-private.log")
	full := filepath.Join(files.Root, relative)
	if _, e = os.Lstat(full); errors.Is(e, os.ErrNotExist) {
		if e = files.Bytes(relative, nil); e != nil {
			return nil, e
		}
	} else if e != nil {
		return nil, e
	}
	if e = files.Check(relative, false); e != nil {
		return nil, e
	}
	return os.OpenFile(full, os.O_WRONLY|os.O_APPEND, 0600)
}

type windowsChildren struct {
	jobs  map[string]*winproc.Job
	exits map[string]*windowsChildExit
}

func (g *windowsChildren) close() {
	for _, j := range g.jobs {
		_ = j.Close()
	}
}
func (g *windowsChildren) launch(run, role string, args, environment []string, cookie string) (Child, error) {
	if old := g.jobs[role]; old != nil {
		_ = old.Close()
	}
	job, e := winproc.NewJob()
	if e != nil {
		return Child{}, e
	}
	g.jobs[role] = job
	log, e := privateLog(run, role)
	if e != nil {
		job.Close()
		return Child{}, e
	}
	defer log.Close()
	in, e := os.Open(os.DevNull)
	if e != nil {
		job.Close()
		return Child{}, e
	}
	var writer *os.File
	if cookie != "" {
		in.Close()
		in, writer, e = os.Pipe()
		if e != nil {
			job.Close()
			return Child{}, e
		}
		defer writer.Close()
	}
	defer in.Close()
	var result Child
	var process *winproc.Process
	e = update(run, func(s *State) error {
		if e := guard(run, s); e != nil {
			return e
		}
		p, e := job.Start(winproc.Spec{Args: args, Directory: private(run), Environment: environment, Stdin: in, Stdout: log, Stderr: log}, func(id platform.Identity) error {
			result = Child{Role: role, PID: id.PID, Birth: id.Birth, Native: &id, Released: true}
			s.Children = append(s.Children, result)
			return save(run, s)
		})
		process = p
		return e
	})
	if e != nil {
		job.Close()
		if process != nil {
			_, _ = process.Wait()
		}
		return Child{}, e
	}
	g.trackExit(role, process.Identity, process.Wait)
	if writer != nil {
		// The child is already running and consuming stdin. Bound the pipe write;
		// a stalled child must not block coordinator cancellation indefinitely.
		done := make(chan error, 1)
		go func() { _, e := io.WriteString(writer, cookie+"\n"); done <- e }()
		select {
		case e = <-done:
		case <-time.After(10 * time.Second):
			e = errors.New("VPN session pipe stalled")
		}
		if e != nil {
			job.Close()
			return Child{}, e
		}
	}
	return result, nil
}
func startWatcher(run string) error {
	s, e := load(run)
	if e != nil {
		return e
	}
	log, e := privateLog(run, "watchdog")
	if e != nil {
		return e
	}
	defer log.Close()
	in, e := os.Open(os.DevNull)
	if e != nil {
		return e
	}
	defer in.Close()
	p, e := winproc.StartIndependent(winproc.Spec{Args: []string{s.Manifest.Executable, "_watch", "--run", run}, Directory: private(run), Stdin: in, Stdout: log, Stderr: log}, func(id platform.Identity) error {
		return update(run, func(s *State) error {
			if e := guard(run, s); e != nil {
				return e
			}
			s.Watcher = id
			return nil
		})
	})
	if e != nil {
		return e
	}
	done := make(chan error, 1)
	go func() {
		code, err := p.Wait()
		if err == nil && code != 0 {
			err = errors.New("independent watchdog exited before readiness")
		}
		done <- err
	}()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s, err := load(run)
		if err != nil {
			return err
		}
		if watcherReady(run, s) == nil {
			return nil
		}
		select {
		case err := <-done:
			if err == nil {
				err = errors.New("independent watchdog exited before readiness")
			}
			return err
		case <-time.After(50 * time.Millisecond):
		}
	}
	return errors.New("independent watchdog readiness timed out")
}
func startVPN(run string, g *windowsChildren) (Child, error) {
	s, e := load(run)
	if e != nil {
		return Child{}, e
	}
	var session auth.Session
	if e = winRead(run, "auth.json", &session); e != nil {
		return Child{}, e
	}
	if e = session.Validate(s.Manifest.Config.VPN); e != nil {
		return Child{}, e
	}
	age := time.Since(session.Created)
	if age < 0 || age > auth.MaxAge {
		return Child{}, errors.New("VPN session expired; run auth")
	}
	token, e := nonce()
	if e != nil {
		return Child{}, e
	}
	// Wintun can retain the previous instance's name while its device is being
	// removed. Reopening that name can fail after CSTP has accepted the cookie.
	// Give each attempt a fresh name; old instances remain governed solely by
	// their journaled GUID/LUID and process identities during cleanup.
	nameID, e := nonce()
	if e != nil {
		return Child{}, e
	}
	vpnName := "NL-VPN-" + nameID[:16]
	adapters, e := winnet.Adapters()
	if e != nil {
		return Child{}, e
	}
	for _, a := range adapters {
		if strings.EqualFold(a.Name, vpnName) {
			return Child{}, errors.New("VPN attempt interface already exists")
		}
	}
	if e = update(run, func(s *State) error {
		if e := guard(run, s); e != nil {
			return e
		}
		s.Windows.LaunchToken = token
		s.Manifest.Binding.VPN = vpnName
		s.VPN.Bootstrap = false
		return nil
	}); e != nil {
		return Child{}, e
	}
	s.Manifest.Binding.VPN = vpnName
	files, id, e := winFiles(run)
	if e != nil {
		return Child{}, e
	}
	// WScript.Run expands environment references. The only embedded path is
	// the protected ProgramData location; user run paths travel in environment.
	if strings.ContainsAny(private(run), "%\r\n\"") {
		return Child{}, errors.New("administrator path cannot be represented by the Windows hook")
	}
	command, _ := json.Marshal(`"` + frozenSelf(run) + `" _hook`)
	shim := "var shell = WScript.CreateObject(\"WScript.Shell\");\nWScript.Quit(shell.Run(" + string(command) + ", 0, true));\n"
	if e = files.Bytes(filepath.Join(id, "vpn-hook.js"), []byte(shim)); e != nil {
		return Child{}, e
	}
	u, _ := url.Parse(s.Manifest.Config.VPN.Server)
	runtime := filepath.Join(private(run), "runtime")
	args := []string{filepath.Join(runtime, "bin", "openconnect.exe"), "--protocol=anyconnect", "--no-proxy", "--no-system-trust", "--cafile=" + filepath.Join(runtime, "certs", "ca-bundle.crt"), "--non-inter", "--no-dtls", "--reconnect-timeout=0", "--cookie-on-stdin", "--servercert=" + session.Fingerprint, "--resolve=" + u.Hostname() + ":" + s.Manifest.Config.VPN.EndpointIPv4, "--interface=" + s.Manifest.Binding.VPN, "--script=" + filepath.Join(private(run), "vpn-hook.js"), s.Manifest.Config.VPN.Server}
	env := append(os.Environ(), "OPENSSL_CONF=NUL", "NETLAUNCH_HOOK_TOKEN="+token, "NETLAUNCH_HOOK_RUN="+run)
	return g.launch(run, "vpn", args, env, session.Cookie)
}
func stopVPN(run string, g *windowsChildren, company *companyRuntime) error {
	company.revoke()
	if e := update(run, func(s *State) error { s.VPN.Bootstrap = false; s.Leases = nil; s.Windows.LaunchToken = ""; return nil }); e != nil {
		return e
	}
	if job := g.jobs["vpn"]; job != nil {
		if e := job.Close(); e != nil {
			return e
		}
	}
	s, e := load(run)
	if e != nil {
		return e
	}
	for _, c := range s.Children {
		if c.Role == "vpn" {
			if e = stopChild(c); e != nil {
				return e
			}
		}
	}
	// A callback can fail after journaling a guard but before publishing VPN
	// state. Release every journaled VPN generation, not only the last published
	// adapter, so a later reconnect cannot accumulate orphaned protection.
	m, e := networkManager(run)
	if e != nil {
		return e
	}
	journal, e := m.Store.Load()
	if e != nil {
		return e
	}
	adapters := map[string]winnet.Adapter{}
	if s.Windows.VPNAdapter.GUID != "" {
		adapters[s.Windows.VPNAdapter.GUID] = s.Windows.VPNAdapter
	}
	for _, g := range journal.Guards {
		if g.State != "restored" {
			adapters[g.Spec.Adapter.GUID] = g.Spec.Adapter
		}
	}
	for _, a := range adapters {
		if e = m.ReleaseVPN(a); e != nil {
			return e
		}
	}
	return update(run, func(s *State) error {
		s.Windows.Guard = nil
		s.Windows.VPNAdapter = winnet.Adapter{}
		s.Windows.VPNAddress = winnet.Address{}
		return nil
	})
}
func configFor(s State, nodes []policy.Node, secret string, company *companyRuntime, tun bool) (map[string]any, error) {
	c, e := policy.Compile(s.Manifest.Config, nodes, s.Manifest.Binding, secret)
	if e != nil {
		return nil, e
	}
	if e = company.configure(c); e != nil {
		return nil, e
	}
	settings := c["tun"].(map[string]any)
	settings["auto-route"] = false
	settings["enable"] = tun
	return c, nil
}
func serve(run string) (returned error) {
	// Windows needs paired capture routes and an independently journaled WFP
	// guard before company host routes may be installed. Keep both public and
	// internal entrypoints closed until native system validation is complete.
	if !windowsFlowIsolationReady {
		return errors.New("Windows flow isolation awaits system validation; no network changes made")
	}

	if _, e := ReadManifest(run); e != nil {
		return e
	}
	files, _, e := winFiles(run)
	if e != nil {
		return e
	}
	unlock, e := files.Lock("active.lock", time.Second)
	if e != nil {
		return errors.New("another coordinator is active")
	}
	defer unlock()
	if data, e := files.Read("active.json", 4096); e == nil {
		var ref struct {
			Run string `json:"run"`
		}
		if json.Unmarshal(data, &ref) != nil {
			return errors.New("invalid global recovery reference")
		}
		if ref.Run != "" {
			old, e := load(ref.Run)
			if e != nil || old.Phase != "stopped" {
				return errors.New("previous administrator run needs recovery first")
			}
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}

	s, e := initialize(run)
	if e != nil {
		if s.Windows != nil {
			_ = recoverRun(run, "initialization_failed")
		}
		return e
	}
	defer func() {
		if returned != nil {
			_ = recoverRun(run, "bootstrap_failed")
		}
	}()
	if e = freezeRuntime(run); e != nil {
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
	if e = winWrite(run, "auth.json", session); e != nil {
		return e
	}
	if e = winWrite(run, "nodes.json", nodes); e != nil {
		return e
	}
	return startFrozenCoordinator(run)
}

// The WFP application identity is a pathname. Only this protected executable
// may own company sockets; the user-writable UAC bootstrap never opens them.
func startFrozenCoordinator(run string) error {
	files, id, e := winFiles(run)
	if e != nil {
		return e
	}
	if e = files.Check(filepath.Join(id, "netlaunch.exe"), false); e != nil {
		return e
	}
	log, e := privateLog(run, "coordinator")
	if e != nil {
		return e
	}
	defer log.Close()
	in, e := os.Open(os.DevNull)
	if e != nil {
		return e
	}
	defer in.Close()
	p, e := winproc.StartIndependent(winproc.Spec{Args: []string{frozenSelf(run), "_run", "--run", run}, Directory: private(run), Stdin: in, Stdout: log, Stderr: log}, func(id platform.Identity) error {
		if !sameExecutable(id.Executable, frozenSelf(run)) {
			return errors.New("frozen coordinator executable differs")
		}
		if e := update(run, func(s *State) error {
			if e := guard(run, s); e != nil {
				return e
			}
			s.Runner = id
			if s.Manifest.ValidationTimeout != 0 {
				if !s.Windows.ValidationDeadline.IsZero() {
					return errors.New("validation deadline cannot be renewed")
				}
				s.Windows.ValidationDeadline = time.Now().Add(s.Manifest.ValidationTimeout)
			}
			return nil
		}); e != nil {
			return e
		}
		// The bootstrap creates both independent processes as siblings. A
		// coordinator may itself be in a job that forbids nested breakaway.
		// It remains suspended until the watcher has acknowledged readiness.
		return startWatcher(run)
	})
	if e != nil {
		return e
	}
	go func() { _, _ = p.Wait() }()
	return nil
}
func verifyFrozenRunner(run string, s State, id platform.Identity) error {
	if !sameProcess(s.Runner, id) || !sameExecutable(id.Executable, frozenSelf(run)) || !sameExecutable(s.Manifest.Executable, frozenSelf(run)) {
		return errors.New("unowned or mutable coordinator executable")
	}
	return nil
}
func runFrozen(run string) (returned error) {
	if !windowsFlowIsolationReady {
		return errors.New("Windows flow isolation awaits system validation; no network changes made")
	}
	files, id, e := winFiles(run)
	if e != nil {
		return e
	}
	if e = files.Check(filepath.Join(id, "netlaunch.exe"), false); e != nil {
		return e
	}
	unlock, e := files.Lock("active.lock", 15*time.Second)
	if e != nil {
		return errors.New("another coordinator is active")
	}
	defer unlock()
	s, e := load(run)
	if e != nil {
		return e
	}
	me, e := platform.Process(os.Getpid())
	if e != nil {
		return e
	}
	if e = verifyFrozenRunner(run, s, me); e != nil {
		return e
	}
	if windowsFlowIsolationReady && s.Windows.ValidationDeadline.IsZero() {
		return errors.New("validation coordinator has no published deadline")
	}
	data, e := files.Read("active.json", 4096)
	if e != nil {
		return e
	}
	var ref struct {
		Run string `json:"run"`
	}
	if json.Unmarshal(data, &ref) != nil || ref.Run != run {
		return errors.New("global coordinator reference differs")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	children := &windowsChildren{jobs: map[string]*winproc.Job{}}
	defer func() {
		cancel()
		children.close()
		reason := "coordinator_exit"
		if errors.Is(returned, errVPNAuthenticationRequired) {
			reason = "authentication_required"
		}
		if returned != nil {
			_ = update(run, func(s *State) error { s.Error = "startup_or_runtime_failed"; return nil })
		}
		_ = recoverRun(run, reason)
	}()
	power, e := winnet.WatchPower()
	if e != nil {
		return e
	}
	defer power.Close()
	windowsPower = power
	if e = freshEpoch(run); e != nil {
		return e
	}
	s, e = load(run)
	if e != nil {
		return e
	}
	var nodes []policy.Node
	if e = winRead(run, "nodes.json", &nodes); e != nil {
		return e
	}
	nodes, e = policy.SanitizeNodes(nodes)
	if e != nil {
		return e
	}
	if platform.ForeignVPN() {
		return errors.New("another OpenConnect is active")
	}
	if e = platform.CheckConflicts(s.Manifest.Network); e != nil {
		return e
	}
	for _, p := range []int{s.Manifest.Config.Ports.Proxy, s.Manifest.Config.Ports.DNS, s.Manifest.Binding.ControllerPort} {
		if !platform.Available(p) {
			return errors.New("requested local port is busy")
		}
	}
	company, e := startCompany(ctx, run)
	if e != nil {
		return e
	}
	// Reserve IPv6 DNS before any takeover. Its lifetime is tied to the owner,
	// while both DNS families are restored by the independent journal watcher.
	dnsBridge, e := dnsloopback.Start(ctx, "[::1]:53", fmt.Sprintf("127.0.0.1:%d", s.Manifest.Config.Ports.DNS))
	if e != nil {
		return e
	}
	defer dnsBridge.Close()
	go func() {
		select {
		case <-dnsBridge.Done:
			cancel()
		case <-ctx.Done():
		}
	}()
	secret, e := nonce()
	if e != nil {
		return e
	}
	config, e := configFor(s, nodes, secret, company, true)
	if e != nil {
		return e
	}
	if e = saveCore(run, config); e != nil {
		return e
	}
	if e = watcherReady(run, s); e != nil {
		return e
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if pulse(run) != nil {
					cancel()
					return
				}
			}
		}
	}()
	if e = endpoint(run, s.Windows.Physical); e != nil {
		return e
	}
	core := filepath.Join(private(run), "runtime", "bin", "mihomo.exe")
	coreChild, e := children.launch(run, "core", []string{core, "-d", private(run), "-f", filepath.Join(private(run), "core.json")}, nil, "")
	if e != nil {
		return e
	}
	if e = wait(ctx, run, 12*time.Second, func() error {
		ok, e := alive(coreChild)
		if e != nil {
			return e
		}
		if !ok {
			return errors.New("core exited")
		}
		return api(run, "GET", "/configs", nil, &map[string]any{})
	}); e != nil {
		return e
	}
	if e = wait(ctx, run, 12*time.Second, func() error { return discoverTUN(run) }); e != nil {
		return e
	}
	vpnChild, e := startVPN(run, children)
	if e != nil {
		return e
	}
	if e = wait(ctx, run, 50*time.Second, func() error {
		if children.vpnAuthenticationRejected() {
			return &terminalReadinessError{errVPNAuthenticationRequired}
		}
		if live, err := alive(vpnChild); err != nil || !live {
			if result, known := children.childExit("vpn"); known && result.identity == *vpnChild.Native {
				return &terminalReadinessError{errors.New("VPN process exited before readiness")}
			}
			return errors.New("waiting for VPN process exit result")
		}
		return company.ready()
	}); e != nil {
		return e
	}
	if e = openCompany(run, company); e != nil {
		company.diagnostic("bootstrap_bound", e)
		return e
	}
	names := []string{}
	for _, n := range nodes {
		names = append(names, n["name"].(string))
	}
	selection := selector.New(names)
	if e = wait(ctx, run, 45*time.Second, func() error {
		if e := choose(run, selection); e != nil {
			return e
		}
		if selection.Current == selector.Reject {
			return errors.New("personal proxy is not ready")
		}
		return nil
	}); e != nil {
		return e
	}
	if e = wait(ctx, run, 12*time.Second, func() error { return capture(run) }); e != nil {
		return e
	}
	if e = takeoverDNS(run); e != nil {
		return e
	}
	if e = wait(ctx, run, 60*time.Second, func() error {
		if e := ensurePersonalSelection(run, selection); e != nil {
			return e
		}
		if e := openCompany(run, company); e != nil {
			return e
		}
		for _, p := range s.Manifest.Config.Probes {
			if e := probe(run, p, false); e != nil {
				company.diagnostic("startup_system_"+p.Channel, e)
				if p.Channel == "personal" {
					if rejectErr := rejectPersonal(run, selection, selection.Current, e); rejectErr != nil {
						return rejectErr
					}
				}
				return e
			}
		}
		return nil
	}); e != nil {
		return e
	}
	if e = update(run, func(s *State) error { s.Phase = "ready"; s.LastReady = time.Now(); return nil }); e != nil {
		return e
	}
	return windowsLoop(ctx, run, children, company, coreChild, nodes, secret, selection, names)
}
func windowsLoop(ctx context.Context, run string, g *windowsChildren, company *companyRuntime, core Child, nodes []policy.Node, secret string, selection *selector.Policy, names []string) error {
	lastHealth, lastProbe, lastAttempt := time.Now(), time.Now(), time.Now()
	disconnected := false
	authenticationRequired := false
	openedGeneration := ""
	for ctx.Err() == nil {
		select {
		case <-company.done:
			return errors.New("company ingress stopped")
		default:
		}
		s, e := load(run)
		if e != nil {
			return e
		}
		if guard(run, &s) != nil {
			return nil
		}
		if ok, e := alive(core); e != nil || !ok {
			return errors.New("owned core exited")
		}
		observed, networkErr := winnet.Discover()
		epoch, awake := windowsPower.Epoch()
		changed := networkErr == nil && (!winnet.SameAdapter(observed.Adapter, s.Windows.Physical.Adapter) || observed.Address != s.Windows.Physical.Address || observed.Gateway != s.Windows.Physical.Gateway)
		resume := !awake || epoch != s.Windows.Epoch
		if networkErr != nil || resume || changed {
			company.revoke()
			_ = gate(run)
			_ = selectPersonal(run, selector.Reject)
			if !disconnected {
				if e = stopVPN(run, g, company); e != nil {
					return e
				}
				disconnected = true
			}
			if networkErr != nil || !awake {
				_ = update(run, func(s *State) error { s.Phase = "network_unavailable"; s.Personal = selector.Reject; return nil })
				time.Sleep(time.Second)
				continue
			}
			if e = freshEpoch(run); e != nil {
				return e
			}
			if changed {
				if e = endpoint(run, observed); e != nil {
					return e
				}
				if e = update(run, func(s *State) error {
					s.Manifest.Binding.Physical = observed.Adapter.Name
					s.Manifest.Network = platform.Network{Interface: observed.Adapter.Name, Address: observed.Address, Gateway: observed.Gateway, Service: observed.Adapter.GUID}
					return nil
				}); e != nil {
					return e
				}
				s, e = load(run)
				if e != nil {
					return e
				}
				config, e := configFor(s, nodes, secret, company, true)
				if e != nil {
					return e
				}
				if e = saveCore(run, config); e != nil {
					return e
				}
				if e = api(run, "PUT", "/configs?force=true", map[string]string{"path": filepath.Join(private(run), "core.json")}, nil); e != nil {
					return e
				}
				if e = capture(run); e != nil {
					return e
				}
				if e = takeoverDNS(run); e != nil {
					return e
				}
			}
			selection = selector.New(names)
			lastHealth, lastProbe, lastAttempt = time.Time{}, time.Time{}, time.Time{}
		}
		if _, e = os.Lstat(filepath.Join(run, "auth-refresh.json")); e == nil {
			var fresh auth.Session
			if e = readJSON(filepath.Join(run, "auth-refresh.json"), &fresh); e != nil {
				return e
			}
			if e = fresh.Validate(s.Manifest.Config.VPN); e != nil {
				return e
			}
			if e = stopVPN(run, g, company); e != nil {
				return e
			}
			disconnected = true
			if e = winWrite(run, "auth.json", fresh); e != nil {
				return e
			}
			authenticationRequired = false
			delete(g.exits, "vpn")
			if e = os.Remove(filepath.Join(run, "auth-refresh.json")); e != nil {
				return e
			}
			lastAttempt = time.Time{}
		}
		vpnAlive := false
		for _, c := range s.Children {
			if c.Role == "vpn" {
				ok, e := alive(c)
				if e != nil {
					return e
				}
				vpnAlive = vpnAlive || ok
			}
		}
		if !vpnAlive && !authenticationRequired && g.vpnAuthenticationRejected() {
			if e = stopVPN(run, g, company); e != nil {
				return e
			}
			authenticationRequired = true
		}
		if authenticationRequired && s.Phase != "authentication_required" {
			if e = update(run, func(s *State) error {
				s.Phase = "authentication_required"
				s.Error = "VPN session rejected; run auth"
				return nil
			}); e != nil {
				return e
			}
		}
		if !authenticationRequired && (!vpnAlive || disconnected) && time.Since(lastAttempt) > 10*time.Second {
			if e = stopVPN(run, g, company); e != nil {
				return e
			}
			if e = freshEpoch(run); e != nil {
				return e
			}
			_, e = startVPN(run, g)
			lastAttempt = time.Now()
			disconnected = false
			if e != nil {
				_ = update(run, func(s *State) error { s.Phase = "authentication_required"; return nil })
			}
			time.Sleep(time.Second)
			continue
		}
		if vpnAlive && (s.Phase != "ready" || s.VPN.Generation != openedGeneration || company.ready() != nil) {
			if e = openCompany(run, company); e != nil {
				company.diagnostic("runtime_bound", e)
				_ = gate(run)
				_ = update(run, func(s *State) error { s.Phase = "company_unavailable"; return nil })
			} else {
				openedGeneration = s.VPN.Generation
				lastProbe = time.Time{}
			}
		}
		if time.Since(lastHealth) > 15*time.Second {
			if e = choose(run, selection); e != nil {
				return e
			}
			lastHealth = time.Now()
		}
		if time.Since(lastProbe) > 30*time.Second {
			readyErr := company.ready()
			ready := readyErr == nil
			if readyErr != nil {
				company.diagnostic("readiness", readyErr)
			}
			for _, p := range s.Manifest.Config.Probes {
				if authenticationRequired && p.Channel == "company" {
					continue
				}
				if e = probe(run, p, false); e != nil {
					company.diagnostic("probe_"+p.Channel, e)
					ready = false
					if p.Channel == "personal" {
						if rejectErr := rejectPersonal(run, selection, selection.Current, e); rejectErr != nil {
							return rejectErr
						}
						lastHealth = time.Time{}
					}
				}
			}
			_ = update(run, func(s *State) error {
				if ready {
					s.Phase = "ready"
					s.LastReady = time.Now()
					s.Error = ""
				} else if s.Phase != "authentication_required" {
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
