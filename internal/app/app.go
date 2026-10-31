// Package app implements the user-facing launcher without coupling policy to an OS.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"netlaunch/internal/auth"
	"netlaunch/internal/buildinfo"
	"netlaunch/internal/engine"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/securefile"
	"netlaunch/internal/subscription"
)

const Version = buildinfo.Version
const Example = `{
  "version": 1,
  "company": {
    "domains": ["gateway.corp.example.com", "git.corp.example.com"],
    "cidrs": [], "dns": ["192.0.2.53"]
  },
  "personal": {
    "domains": ["www.gstatic.com"], "cidrs": [],
    "dns": ["https://1.1.1.1/dns-query"]
  },
  "direct_dns": ["223.5.5.5"],
  "vpn": {"server": "https://vpn.example.com:4433", "endpoint_ipv4": "192.0.2.1"},
  "ports": {"proxy": 17890, "dns": 53},
  "probes": [
    {"url": "https://gateway.corp.example.com:8443/", "channel": "company"},
    {"url": "https://git.corp.example.com/", "channel": "company"},
    {"url": "https://www.gstatic.com/generate_204", "channel": "personal"},
    {"url": "https://www.baidu.com/", "channel": "direct"}
  ]
}
`

type CLI struct{ Out, Err io.Writer }
type options struct {
	profile, runtime, file, run string
	index                       int
	force                       bool
	prepareOnly                 bool
	validationTimeout           time.Duration
	sessionTimeout              time.Duration
}

func DefaultProfile() (string, error) { return defaultProfilePath() }
func (c CLI) Run(args []string) error {
	if c.Out == nil {
		c.Out = io.Discard
	}
	if c.Err == nil {
		c.Err = io.Discard
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Fprintln(c.Out, "NetLaunch "+Version+"\nCommands: init, import, sync, plan, config validate|diff|apply|rollback|history, rules explain TARGET, doctor, check-runtime, auth, up, status, down, version, diagnostics export\nOptions: --profile DIR --runtime DIR; init --file POLICY_OR_BOOTSTRAP.json; import --file FILE; config validate|diff|apply --file POLICY.json; config apply|rollback --restart; config rollback --revision SHA256; up --prepare-only; version --json\nmacOS network lifecycle is experimental; config apply/rollback changes the next-start policy unless --restart is specified. Diagnostics exports allowlisted saved status to stdout; it does not check live network health.")
		return nil
	}
	if args[0] == "version" {
		return c.version(args[1:])
	}
	if args[0] == "diagnostics" {
		return c.diagnostics(args[1:])
	}
	if args[0] == "config" || args[0] == "rules" {
		return c.maintenance(args)
	}
	profile, e := DefaultProfile()
	if e != nil {
		return e
	}
	executable, e := os.Executable()
	if e != nil {
		return e
	}
	opts := options{}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(c.Err)
	fs.StringVar(&opts.profile, "profile", profile, "private local profile directory")
	fs.StringVar(&opts.runtime, "runtime", filepath.Join(filepath.Dir(executable), "runtime"), "bundled runtime directory")
	fs.StringVar(&opts.file, "file", "", "policy/bootstrap for init, or node file for import")
	fs.StringVar(&opts.run, "run", "", "specific run directory")
	fs.IntVar(&opts.index, "index", -1, "internal child journal index")
	fs.BoolVar(&opts.force, "force", false, "refresh the local VPN session")
	fs.BoolVar(&opts.prepareOnly, "prepare-only", false, "up: stage a private run without administrator authorization or network changes")
	fs.DurationVar(&opts.validationTimeout, "validation-timeout", 0, "up: hard deadline, required in Windows validation builds (1s through 45m)")
	fs.DurationVar(&opts.sessionTimeout, "session-timeout", 0, "up: Windows home preview session limit (default 8h, maximum 12h)")
	if e = fs.Parse(args[1:]); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if e = validateLaunchOptions(&opts, args[0]); e != nil {
		return e
	}
	opts.profile, e = filepath.Abs(opts.profile)
	if e != nil {
		return e
	}
	opts.runtime, e = filepath.Abs(opts.runtime)
	if e != nil {
		return e
	}
	if opts.file != "" {
		opts.file, e = filepath.Abs(opts.file)
		if e != nil {
			return errors.New("input file path unavailable")
		}
	}
	switch args[0] {
	case "check-runtime":
		result, checkErr := runtimebundle.Check(context.Background(), opts.runtime)
		if e := c.json(result); e != nil {
			return e
		}
		return checkErr
	case "_serve", "_run", "_watch", "_recover", "_hook":
		return engine.Internal(args[0][1:], opts.run)
	case "_child":
		return engine.ChildMain(opts.run, opts.index)
	case "_auth":
		return c.authenticate(opts)
	case "init":
		if _, e = os.Lstat(filepath.Join(opts.profile, "policy.json")); !errors.Is(e, os.ErrNotExist) {
			return errors.New("profile already exists; existing policy was not overwritten")
		}
		data := []byte(Example)
		if opts.file != "" {
			data, e = securefile.Read(opts.file, 1<<20, false)
			if e != nil {
				return errors.New("could not read a bounded regular policy file")
			}
		}
		var envelope map[string]json.RawMessage
		var sources *subscription.Sources
		if json.Unmarshal(data, &envelope) == nil && envelope["policy"] != nil {
			b, err := subscription.Decode(data, filepath.Dir(opts.file))
			if err != nil {
				return errors.New("bootstrap file is invalid; profile was not initialized")
			}
			data, e = json.MarshalIndent(b.Policy, "", "  ")
			if e != nil {
				return e
			}
			sources = &b.Subscriptions
		}
		if _, e = policy.Decode(data); e != nil {
			return errors.New("policy file is invalid; profile was not initialized")
		}
		if e = initializeProfile(opts.profile, data, sources); e != nil {
			return e
		}
		if opts.file == "" {
			fmt.Fprintln(c.Out, "Created example policy:", filepath.Join(opts.profile, "policy.json"))
			fmt.Fprintln(c.Out, "Replace example VPN endpoint and company DNS before use, then import your node file.")
		} else {
			fmt.Fprintln(c.Out, "Initialized private local policy. Use sync for configured subscriptions, or import a node file; no network changes were made.")
		}
		return nil
	case "status":
		return c.status(opts)
	case "down":
		return c.down(opts)
	case "up":
		return c.startProfile(opts)
	}
	if args[0] == "sync" || args[0] == "import" {
		unlock, err := securefile.Lock(filepath.Join(opts.profile, "launch.lock"), time.Second)
		if err != nil {
			return err
		}
		defer unlock()
		if err := requireCompleteConfigTransaction(opts.profile); err != nil {
			return err
		}
	}
	cfg, e := readPolicy(opts.profile)
	if e != nil {
		return e
	}
	if args[0] == "sync" {
		return c.syncSubscriptions(opts, cfg, true)
	}
	if args[0] == "import" {
		if _, present, err := sourceConfig(opts.profile); err != nil {
			return err
		} else if present {
			return errors.New("subscriptions configured; use sync instead of manual import")
		}
		if opts.file == "" {
			return errors.New("import requires --file")
		}
		b, e := securefile.Read(opts.file, 4<<20, false)
		if e != nil {
			return errors.New("could not read a bounded regular node file")
		}
		nodes, issues, e := policy.ImportSupportedNodes(b)
		for _, issue := range issues {
			fmt.Fprintf(c.Out, "Skipped subscription entry %d: %s.\n", issue.Index, issue.Reason)
		}
		if e != nil {
			return e
		}
		if e = policy.ValidateEndpoints(cfg, nodes); e != nil {
			return e
		}
		if e = securefile.Write(filepath.Join(opts.profile, "nodes.json"), nodes); e != nil {
			return e
		}
		if e = securefile.Write(filepath.Join(opts.profile, "import-result.json"), map[string]any{"imported": len(nodes), "skipped": issues}); e != nil {
			return e
		}
		fmt.Fprintf(c.Out, "Imported %d nodes. Subscription rules, DNS, groups, TUN and interface bindings were discarded.\n", len(nodes))
		return nil
	}
	if args[0] == "auth" {
		run, runErr := currentRun(opts)
		if runErr == nil {
			if st, e := statusFor(run); e == nil && requiresFreshAuthentication(opts.profile, cfg, st) {
				opts.force = true
			}
		}
		if e := c.obtainAuth(opts, cfg); e != nil {
			return e
		}
		if runErr == nil {
			if st, e := statusFor(run); e == nil && st.Phase != "stopped" && st.Phase != "recovery_failed" {
				session, ok := auth.Load(opts.profile, cfg.VPN)
				if !ok {
					return errors.New("no valid session to refresh")
				}
				return securefile.Write(filepath.Join(run, "auth-refresh.json"), session)
			}
		}
		return nil
	}
	cfg, nodes, e := effectiveProfile(opts.profile, cfg)
	if e != nil {
		return e
	}
	if e = policy.ValidateEndpoints(cfg, nodes); e != nil {
		return e
	}
	switch args[0] {
	case "plan":
		// Only the policy is printed. Node credentials and controller secrets never appear here.
		return c.json(map[string]any{"version": Version, "company": cfg.Company, "personal": cfg.Personal, "default_exit": "physical", "failure_exit": "reject", "vpn": cfg.VPN, "probes": cfg.Probes, "node_count": len(nodes), "personal_rules": cfg.PersonalRules, "native_platform": platform.Supported(), "network_changes": false})
	case "doctor":
		issues, ports := diagnose(opts, cfg)
		if e = c.json(map[string]any{"version": Version, "platform": runtime.GOOS + "/" + runtime.GOARCH, "ready_for_start": len(issues) == 0, "issues": issues, "port_checks": ports, "privileged_port_check_required": runtime.GOOS == "darwin", "network_changes": false}); e != nil {
			return e
		}
		if len(issues) > 0 {
			return errors.New("startup prerequisites are not satisfied")
		}
		return nil
	default:
		return errors.New("unknown command; run netlaunch help")
	}
}
func (c CLI) json(v any) error {
	e := json.NewEncoder(c.Out)
	e.SetIndent("", "  ")
	return e.Encode(v)
}
func readPolicy(profile string) (policy.Config, error) {
	b, e := securefile.Read(filepath.Join(profile, "policy.json"), 1<<20, false)
	if e != nil {
		return policy.Config{}, errors.New("policy missing or unreadable; run init first")
	}
	return policy.Decode(b)
}
func readNodes(profile string) ([]policy.Node, error) {
	b, e := securefile.Read(filepath.Join(profile, "nodes.json"), 4<<20, true)
	if e != nil {
		return nil, errors.New("private node cache missing; run import first")
	}
	var n []policy.Node
	if json.Unmarshal(b, &n) != nil {
		return nil, errors.New("invalid private node cache")
	}
	return policy.SanitizeNodes(n)
}
func diagnose(o options, c policy.Config) ([]string, []platform.PortCheck) {
	issues := []string{}
	if !platform.Supported() {
		issues = append(issues, "Native network takeover is not enabled on this platform in this preview.")
		if runtime.GOOS != "windows" {
			return issues, nil
		}
		// Windows can still diagnose the bundle and network without opening up.

	}
	if c.VPN.EndpointIPv4 == "192.0.2.1" || c.VPN.Server == "https://vpn.example.com:4433" {
		issues = append(issues, "Replace the example VPN and company DNS settings.")
	}
	if c.Ports.DNS != 53 {
		issues = append(issues, "System DNS takeover requires local port 53.")
	}
	if _, e := runtimebundle.Verify(o.runtime); e != nil {
		issues = append(issues, e.Error())
	}
	n, e := platform.Discover()
	if e != nil {
		issues = append(issues, e.Error())
	} else if e = platform.CheckConflicts(n); e != nil {
		issues = append(issues, e.Error())
	}
	if platform.ForeignVPN() {
		issues = append(issues, "Another OpenConnect process is active.")
	}
	ports, failures := platform.PreflightPorts([]int{c.Ports.Proxy, c.Ports.DNS})
	for _, e := range failures {
		issues = append(issues, e.Error())
	}
	return issues, ports
}
func currentRun(o options) (string, error) {
	if o.run != "" {
		return o.run, engine.ValidateRun(o.run)
	}
	b, e := securefile.Read(filepath.Join(o.profile, "current.json"), 4096, true)
	if e != nil {
		return "", errors.New("no current run")
	}
	var ref struct {
		Run string `json:"run"`
	}
	if json.Unmarshal(b, &ref) != nil {
		return "", errors.New("invalid run reference")
	}
	return ref.Run, engine.ValidateRun(ref.Run)
}
func statusFor(run string) (engine.Status, error) {
	b, e := securefile.Read(filepath.Join(run, "status.json"), 65536, true)
	if e != nil {
		return engine.Status{}, errors.New("status not yet available; use down if startup did not finish")
	}
	var s engine.Status
	e = json.Unmarshal(b, &s)
	return engine.RefreshStatus(s, time.Now()), e
}
func (c CLI) status(o options) error {
	run, e := currentRun(o)
	if e != nil {
		return e
	}
	s, e := statusFor(run)
	if e != nil {
		return e
	}
	return c.json(map[string]any{"run": run, "status": s, "stale": s.Phase != "stopped" && s.Phase != "prepared" && time.Since(s.Updated) > 40*time.Second})
}
func (c CLI) down(o options) error {
	if !platform.Supported() {
		return errors.New("native lifecycle unavailable on this platform")
	}
	run, e := currentRun(o)
	if e != nil {
		return e
	}
	if s, e := statusFor(run); e == nil && s.Phase == "stopped" {
		fmt.Fprintln(c.Out, "Already stopped.")
		return nil
	}
	if e = securefile.Bytes(filepath.Join(run, "STOP"), nil); e != nil {
		return e
	}
	fmt.Fprintln(c.Out, "Stop requested. Waiting for the independent recovery process…")
	for i := 0; i < 20; i++ {
		s, e := statusFor(run)
		if e == nil && s.Phase == "stopped" {
			fmt.Fprintln(c.Out, "Owned processes and routes stopped; DNS restored.")
			return nil
		}
		time.Sleep(time.Second)
	}
	fmt.Fprintln(c.Out, "Requesting administrator authorization to finish recovery…")
	if e = engine.Launch("recover", run); e != nil {
		return e
	}
	s, e := statusFor(run)
	if e != nil || s.Phase != "stopped" {
		return errors.New("recovery is incomplete; preserve this run directory and retry down")
	}
	fmt.Fprintln(c.Out, "Recovery complete.")
	return nil
}
func (c CLI) startProfile(o options) error {
	if e := securefile.Dir(o.profile); e != nil {
		return e
	}
	unlock, e := securefile.Lock(filepath.Join(o.profile, "launch.lock"), time.Second)
	if e != nil {
		return e
	}
	defer unlock()
	if e := requireCompleteConfigTransaction(o.profile); e != nil {
		return e
	}
	cfg, e := readPolicy(o.profile)
	if e != nil {
		return e
	}
	if e = c.syncSubscriptions(o, cfg, false); e != nil {
		return e
	}
	cfg, nodes, e := effectiveProfile(o.profile, cfg)
	if e != nil {
		return e
	}
	return c.upLocked(o, cfg, nodes)
}

// The caller holds launch.lock from configuration read through readiness.
func (c CLI) upLocked(o options, cfg policy.Config, nodes []policy.Node) error {
	if !platform.Supported() {
		return errors.New("native lifecycle unavailable on this platform")
	}
	if e := policy.ValidateEndpoints(cfg, nodes); e != nil {
		return e
	}
	var e error
	if run, e := currentRun(o); e == nil {
		if s, e := statusFor(run); e != nil || s.Phase != "stopped" {
			return errors.New("a previous run needs attention; run status or down first")
		} else if requiresFreshAuthentication(o.profile, cfg, s) {
			o.force = true
		}
	}
	if issues, _ := diagnose(o, cfg); len(issues) > 0 {
		for _, i := range issues {
			fmt.Fprintln(c.Err, i)
		}
		return errors.New("startup stopped before authentication or network changes; resolve doctor findings first")
	}
	if e = c.obtainAuth(o, cfg); e != nil {
		return e
	}
	session, ok := auth.Load(o.profile, cfg.VPN)
	if !ok {
		return errors.New("local VPN session is unavailable")
	}
	network, e := platform.Discover()
	if e != nil {
		return e
	}
	vpn, tun, e := platform.Candidates()
	if e != nil {
		return e
	}
	port, e := platform.FreePort()
	if e != nil {
		return e
	}
	runRoot := filepath.Join(o.profile, "runs")
	if e := securefile.Dir(runRoot); e != nil {
		return e
	}
	tmp, e := filepath.EvalSymlinks(runRoot)
	if e != nil {
		return e
	}
	run, e := securefile.TempDir(tmp, "netlaunch-")
	if e != nil {
		return e
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(run)
		}
	}()
	self, e := os.Executable()
	if e != nil {
		return e
	}
	staged := filepath.Join(run, stagedExecutableName())
	if e = copyBinary(self, staged); e != nil {
		return e
	}
	owner, ownerSID, e := engine.OwnerIdentity()
	if e != nil {
		return e
	}
	m := engine.Manifest{Version: 1, Owner: owner, OwnerSID: ownerSID, Config: cfg, Binding: policy.Binding{Physical: network.Interface, VPN: vpn, TUN: tun, ControllerPort: port}, Network: network, Executable: staged, Created: time.Now()}
	m.ValidationTimeout = o.validationTimeout
	if e = securefile.Write(filepath.Join(run, "manifest.json"), m); e != nil {
		return e
	}
	if e = runtimebundle.Copy(o.runtime, filepath.Join(run, "runtime")); e != nil {
		return e
	}
	if e = securefile.Write(filepath.Join(run, "nodes.json"), nodes); e != nil {
		return e
	}
	if e = securefile.Write(filepath.Join(run, "auth.json"), session); e != nil {
		return e
	}
	recovery, e := writeRecoveryEntry(run, staged)
	if e != nil {
		return e
	}
	if e = securefile.Write(filepath.Join(o.profile, "current.json"), map[string]string{"run": run}); e != nil {
		return e
	}
	published = true
	fmt.Fprintln(c.Out, "This preview will create its own VPN/TUN and change this network service's DNS.")
	fmt.Fprintln(c.Out, "If the connection does not recover within 2 minutes, open:", recovery)
	if o.prepareOnly {
		return c.prepared(run)
	}
	fmt.Fprintln(c.Out, "Administrator authorization will now appear.")
	if e = engine.Launch("serve", run); e != nil {
		return e
	}
	for i := 0; i < 150; i++ {
		s, e := statusFor(run)
		if e == nil {
			if s.Phase == "ready" {
				return c.json(s)
			}
			if s.Phase == "stopped" || s.Phase == "recovery_failed" {
				if engine.NeedsAuthentication(s) {
					return errors.New("VPN authentication was rejected or expired; run auth, then up")
				}
				return errors.New("startup did not complete; inspect status and use the recovery entry")
			}
		}
		time.Sleep(time.Second)
	}
	return errors.New("startup readiness deadline exceeded; use status or the recovery entry")
}

func requiresFreshAuthentication(profile string, cfg policy.Config, status engine.Status) bool {
	if !engine.NeedsAuthentication(status) {
		return false
	}
	if status.Phase == "stopped" {
		if session, valid := auth.Load(profile, cfg.VPN); valid && session.Created.After(status.Updated) {
			return false
		}
	}
	return true
}

// A batch supervisor can activate this staged run within its existing, scoped
// administrator task. The regular up path still requests authorization itself.
func (c CLI) prepared(run string) error {
	status := engine.Status{Phase: "prepared", Updated: time.Now(), Company: "unavailable", Personal: "REJECT", Experimental: true}
	if e := securefile.Write(filepath.Join(run, "status.json"), status); e != nil {
		return e
	}
	return c.json(map[string]any{"run": run, "phase": "prepared", "network_changes": false, "administrator_authorization_requested": false})
}
func copyBinary(from, to string) error {
	f, e := os.Open(from)
	if e != nil {
		return e
	}
	defer f.Close()
	out, e := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if e != nil {
		return e
	}
	_, e = io.Copy(out, f)
	ce := out.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return sealStaged(to)
}

func validateLaunchOptions(o *options, command string) error {
	if o.prepareOnly && command != "up" {
		return errors.New("--prepare-only is only valid with up")
	}
	if o.validationTimeout != 0 && (command != "up" || !platform.WindowsValidationBuild) {
		return errors.New("--validation-timeout requires up in a windows_validation build")
	}
	if command == "up" && platform.WindowsValidationBuild && (o.validationTimeout < time.Second || o.validationTimeout > 45*time.Minute) {
		return errors.New("Windows validation requires an explicit --validation-timeout between 1s and 45m")
	}
	if o.sessionTimeout != 0 && (command != "up" || !platform.WindowsHomeBuild || platform.WindowsValidationBuild) {
		return errors.New("--session-timeout requires up in a windows_home build")
	}
	if command == "up" && platform.WindowsHomeBuild {
		if platform.WindowsValidationBuild {
			return errors.New("windows_home and windows_validation build tags cannot be combined")
		}
		value, e := homeSessionTimeout(o.sessionTimeout)
		if e != nil {
			return e
		}
		o.validationTimeout = value
	}
	return nil
}
