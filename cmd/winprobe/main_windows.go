//go:build windows

// winprobe is an opt-in native validation runner. The initial idle mode proves
// independent recovery without modifying network configuration.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"netlaunch/internal/platform"
	"netlaunch/internal/securefile"
	"netlaunch/internal/winnet"
	"netlaunch/internal/winproc"
	"netlaunch/internal/winstate"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type plan struct {
	Owner     platform.Identity `json:"owner"`
	Deadline  time.Time         `json:"deadline"`
	Timeout   time.Duration     `json:"timeout"`
	BootID    string            `json:"boot_id"`
	Stage     string            `json:"stage,omitempty"`
	Fault     string            `json:"fault,omitempty"`
	EarlyExit bool              `json:"early_exit,omitempty"`
}

var validID = regexp.MustCompile(`^netlaunch-[a-f0-9]{32}$`)

func read(files securefile.AdminStore, id, name string, value any) error {
	b, e := files.Read(filepath.Join(id, name), 4<<20)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, value)
}

func manager(files securefile.AdminStore, id string) winstate.Manager {
	return winstate.Manager{Store: probeStore{winstate.NativeStorage{Files: files, RunID: id}}, Native: winstate.NativeBackend{}}
}

func recoverProbe(files securefile.AdminStore, id, reason string) error {
	unlock, e := files.Lock(filepath.Join(id, "probe-recovery.lock"), 15*time.Second)
	if e != nil {
		return e
	}
	defer unlock()
	var p plan
	if e = read(files, id, "probe-plan.json", &p); e != nil {
		return e
	}
	if p.Owner.PID == os.Getpid() {
		return errors.New("recovery must run independently")
	}
	// Kill only the published native identity, and await exit before rollback:
	// a stalled writer cannot resume and install changes after recovery.
	actual, e := platform.Process(p.Owner.PID)
	if e != nil {
		return e
	}
	if actual == p.Owner {
		if e = platform.StopIdentity(p.Owner); e != nil {
			return e
		}
	}
	until := time.Now().Add(10 * time.Second)
	for {
		actual, err := platform.Process(p.Owner.PID)
		if err != nil {
			return err
		}
		if actual != p.Owner {
			break
		}
		if time.Now().After(until) {
			return errors.New("probe owner did not exit")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if e = restoreRouteMutation(files, id); e != nil {
		return fmt.Errorf("restore fixture mutation: %w", e)
	}
	if e = manager(files, id).Recover(); e != nil {
		return fmt.Errorf("recover network journal: %w", e)
	}
	if e = releaseAdapter(files, id); e != nil {
		return fmt.Errorf("release probe adapter: %w", e)
	}
	// Repeated manual verification must not erase the original timeout/exit
	// evidence. Recovery above still rechecks the journal and adapter closure.
	var previous map[string]any
	if read(files, id, "probe-result.json", &previous) == nil && previous["recovered"] == true {
		return nil
	}
	return files.Write(filepath.Join(id, "probe-result.json"), map[string]any{"recovered": true, "reason": reason, "finished": time.Now()})
}

func watch(files securefile.AdminStore, id string) error {
	var p plan
	if e := read(files, id, "probe-plan.json", &p); e != nil {
		return e
	}
	if p.Timeout < time.Second || p.Timeout > 2*time.Minute || p.Owner.PID < 2 {
		return errors.New("invalid probe deadline")
	}
	boot, e := winnet.BootID()
	if e != nil {
		return e
	}
	if boot != p.BootID {
		return automaticRecover(files, id, "boot_changed")
	}
	duration := time.Until(p.Deadline)
	if duration > p.Timeout {
		duration = p.Timeout
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	// Publication is the barrier: no experiment may start before this file.
	if e = files.Write(filepath.Join(id, "probe-ready.json"), true); e != nil {
		return e
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-timer.C:
			return automaticRecover(files, id, "deadline")
		case <-tick.C:
			var result map[string]any
			if read(files, id, "probe-result.json", &result) == nil && result["recovered"] == true {
				return nil
			}
			actual, err := platform.Process(p.Owner.PID)
			if err != nil {
				return err
			}
			if actual != p.Owner {
				return automaticRecover(files, id, "owner_exited")
			}
		}
	}
}

// Native resource disappearance can lag process exit. Preserve the first
// failure and retry the same ownership-checked recovery once, independently
// of the launching session. A retry never broadens cleanup authority.
func automaticRecover(files securefile.AdminStore, id, reason string) error {
	for attempt := 1; attempt <= 2; attempt++ {
		e := recoverProbe(files, id, reason)
		if e == nil {
			return nil
		}
		writeErr := files.Write(filepath.Join(id, fmt.Sprintf("probe-recovery-attempt-%d.json", attempt)), map[string]any{
			"reason": reason, "attempt": attempt, "error": e.Error(), "time": time.Now(),
		})
		if writeErr != nil || attempt == 2 {
			return errors.Join(e, writeErr)
		}
		time.Sleep(time.Second)
	}
	return nil
}

func idle(files securefile.AdminStore, ttl time.Duration, earlyExit bool, stage, runtimeRoot, fault string) error {
	if ttl < time.Second || ttl > 2*time.Minute {
		return errors.New("timeout must be 1s through 2m")
	}
	nonce := make([]byte, 16)
	if _, e := rand.Read(nonce); e != nil {
		return e
	}
	id := "netlaunch-" + hex.EncodeToString(nonce)
	if e := files.Dir(id); e != nil {
		return e
	}
	owner, e := platform.Process(os.Getpid())
	if e != nil {
		return e
	}
	boot, e := winnet.BootID()
	if e != nil {
		return e
	}
	p := plan{Owner: owner, Deadline: time.Now().Add(ttl), Timeout: ttl, BootID: boot, Stage: stage, Fault: fault, EarlyExit: earlyExit}
	if e = files.Write(filepath.Join(id, "probe-plan.json"), p); e != nil {
		return e
	}
	if e = manager(files, id).Store.Save(winstate.Journal{Version: 1, BootID: boot}); e != nil {
		return e
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	b, e := os.ReadFile(self)
	if e != nil {
		return e
	}
	if e = files.Bytes(filepath.Join(id, "winprobe.exe"), b); e != nil {
		return e
	}
	if stage != "" {
		if e = stageRuntime(files, id, runtimeRoot); e != nil {
			return e
		}
	}
	frozen := filepath.Join(files.Root, id, "winprobe.exe")
	// A manual local entry remains usable after the launching process exits.
	// Double-click requests elevation only when needed. /nopause is reserved
	// for bounded automated verification of the exact local recovery entry.
	quoted := "'" + strings.ReplaceAll(frozen, "'", "''") + "'"
	entry := "@echo off\r\nsetlocal\r\npowershell.exe -NoProfile -Command \"" +
		"$p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()); " +
		"if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ & " + quoted + " recover --run " + id + "; exit $LASTEXITCODE }; " +
		"try { $c=Start-Process -FilePath " + quoted + " -ArgumentList 'recover','--run','" + id + "' -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $c.ExitCode } catch { exit 1 }\"\r\n" +
		"set result=%errorlevel%\r\necho Recovery exit code: %result%\r\nif /I not \"%~1\"==\"/nopause\" pause\r\nexit /b %result%\r\n"
	if e = files.Bytes(filepath.Join(id, "recover.cmd"), []byte(entry)); e != nil {
		return e
	}
	if e = files.Bytes(filepath.Join(id, "probe-foreign.exe"), b); e != nil {
		return e
	}
	input, e := os.Open(os.DevNull)
	if e != nil {
		return e
	}
	defer input.Close()
	ownerChild, e := winproc.StartIndependent(winproc.Spec{Args: []string{frozen, "probe-owner", "--run", id}, Directory: filepath.Join(files.Root, id), Stdin: input, Stdout: os.Stdout, Stderr: os.Stderr}, func(who platform.Identity) error {
		p.Owner = who
		if e := files.Write(filepath.Join(id, "probe-plan.json"), p); e != nil {
			return e
		}
		if e := armWatcher(files, id, frozen); e != nil {
			return e
		}
		if stage != "" {
			roles := []string{""}
			if stage == "pair" || stage == "mutation" {
				roles = append(roles, "-tun")
			}
			for _, role := range roles {
				holder, e := winproc.StartIndependent(winproc.Spec{Args: []string{frozen, "hold-adapter", "--run", id, "--role=" + role}, Directory: filepath.Join(files.Root, id)}, func(who platform.Identity) error {
					return files.Write(filepath.Join(id, "probe-holder"+role+".json"), who)
				})
				if e != nil {
					return e
				}
				go holder.Wait()
			}
		}
		return nil
	})
	if e != nil {
		return e
	}
	fmt.Println(filepath.Join(files.Root, id))
	code, e := ownerChild.Wait()
	if e != nil {
		return e
	}
	if code != 0 {
		return fmt.Errorf("probe owner exit %d", code)
	}
	return nil
}

func armWatcher(files securefile.AdminStore, id, frozen string) error {
	child, e := winproc.StartIndependent(winproc.Spec{Args: []string{frozen, "watch", "--run", id}, Directory: filepath.Join(files.Root, id)}, func(identity platform.Identity) error {
		return files.Write(filepath.Join(id, "probe-watcher.json"), identity)
	})
	if e != nil {
		return e
	}
	done := make(chan error, 1)
	go func() {
		code, err := child.Wait()
		if err == nil && code != 0 {
			err = fmt.Errorf("watchdog exit %d", code)
		}
		done <- err
	}()
	until := time.Now().Add(10 * time.Second)
	for {
		var ready bool
		if read(files, id, "probe-ready.json", &ready) == nil && ready {
			break
		}
		select {
		case err := <-done:
			return fmt.Errorf("watchdog exited before readiness: %v", err)
		default:
		}
		if time.Now().After(until) {
			return errors.New("watchdog readiness timeout")
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

func runOwner(files securefile.AdminStore, id string) error {
	var p plan
	if e := read(files, id, "probe-plan.json", &p); e != nil {
		return e
	}
	me, e := platform.Process(os.Getpid())
	if e != nil {
		return e
	}
	if me != p.Owner {
		return errors.New("unpublished probe owner")
	}
	if p.Stage != "" {
		for {
			var goNow bool
			if read(files, id, "probe-go.json", &goNow) == nil && goNow {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if e = nativeProbe(files, id, p.Stage); e != nil {
			return e
		}
	}
	if p.EarlyExit {
		return nil
	}
	// Intentional stalled owner. The independent watchdog must terminate it.
	select {
	case <-time.After(p.Timeout + 15*time.Second):
		return errors.New("watchdog did not terminate owner")
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: winprobe idle|watch|recover [--run ID] [--timeout 20s] [--exit-owner]")
	}
	fs := flag.NewFlagSet("winprobe", flag.ContinueOnError)
	id := fs.String("run", "", "owned probe run identifier")
	ttl := fs.Duration("timeout", 20*time.Second, "non-renewable deadline (maximum 2m)")
	early := fs.Bool("exit-owner", false, "exit after watchdog readiness")
	stage := fs.String("stage", "", "opt-in native stage: adapter, native, pair, mutation; waits for begin")
	runtimeRoot := fs.String("runtime", "", "verified bundled runtime directory")
	role := fs.String("role", "", "internal adapter role")
	fault := fs.String("fault", "", "opt-in transaction interruption point")
	if e := fs.Parse(os.Args[2:]); e != nil {
		return e
	}
	if *role != "" && *role != "-tun" {
		return errors.New("invalid adapter role")
	}
	if *fault != "" && !(validPairFault(*fault) && *stage == "pair") && !(*fault == "route-replaced" && *stage == "mutation") {
		return errors.New("unsupported fault stage")
	}
	files, e := securefile.OpenAdminStore()
	if e != nil {
		return e
	}
	if os.Args[1] == "idle" {
		if *stage != "" && *stage != "adapter" && *stage != "native" && *stage != "pair" && *stage != "mutation" {
			return errors.New("unsupported native stage")
		}
		return idle(files, *ttl, *early, *stage, *runtimeRoot, *fault)
	}
	if !validID.MatchString(*id) {
		return errors.New("invalid probe run ID")
	}
	switch os.Args[1] {
	case "probe-owner":
		return runOwner(files, *id)
	case "dial-foreign":
		return foreignProbe(files, *id)
	case "begin":
		return files.Write(filepath.Join(*id, "probe-go.json"), true)
	case "hold-adapter":
		return holdAdapter(files, *id, *role)
	case "watch":
		return watch(files, *id)
	case "recover":
		return recoverProbe(files, *id, "manual")
	default:
		return errors.New("unknown probe command")
	}
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
