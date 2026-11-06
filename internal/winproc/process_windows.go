//go:build windows

// Package winproc creates suspended Windows children, assigns them to an
// owned kill-on-close job, publishes their identity, then starts execution.
package winproc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"netlaunch/internal/platform"
)

type Job struct {
	mu     sync.Mutex
	handle windows.Handle
}
type Process struct {
	Identity platform.Identity
	handle   windows.Handle
}
type Spec struct {
	Args                  []string
	Directory             string
	NewConsole            bool
	Stdin, Stdout, Stderr *os.File
	Environment           []string
}

var isProcessInJobProc = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

func independentJobPreflight() error {
	var inside uint32
	ok, _, err := isProcessInJobProc.Call(uintptr(windows.CurrentProcess()), 0, uintptr(unsafe.Pointer(&inside)))
	if ok == 0 {
		return fmt.Errorf("inspect independent parent job: %w", err)
	}
	if inside == 0 {
		return nil
	}
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	var size uint32
	if err := windows.QueryInformationJobObject(0, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)), &size); err != nil {
		return fmt.Errorf("inspect independent parent job limits: %w", err)
	}
	if size != uint32(unsafe.Sizeof(limits)) {
		return errors.New("independent parent job limits are incomplete")
	}
	// Nested jobs may retain the child in a non-breakaway job even when
	// CreateProcess accepts CREATE_BREAKAWAY_FROM_JOB. Do not publish a
	// recovery process when the caller's immediate job forbids independence.
	if limits.BasicLimitInformation.LimitFlags&(windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK|windows.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) == 0 {
		return fmt.Errorf("independent parent job forbids breakaway: %w", windows.ERROR_ACCESS_DENIED)
	}
	return nil
}

func NewJob() (*Job, error) {
	h, e := windows.CreateJobObject(nil, nil)
	if e != nil {
		return nil, e
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, e = windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); e != nil {
		windows.CloseHandle(h)
		return nil, e
	}
	return &Job{handle: h}, nil
}
func (j *Job) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.handle == 0 {
		return nil
	}
	e := windows.CloseHandle(j.handle)
	j.handle = 0
	return e
}

func environmentBlock(values []string) ([]uint16, error) {
	if values == nil {
		return nil, nil
	}
	// Last value wins, like os/exec, with Windows' case-insensitive keys.
	entries := map[string]string{}
	for _, s := range values {
		at := strings.IndexByte(s, '=')
		if at == 0 {
			at = strings.IndexByte(s[1:], '=') + 1
		}
		if at <= 0 || strings.IndexByte(s, 0) >= 0 {
			return nil, errors.New("invalid child environment")
		}
		entries[strings.ToUpper(s[:at])] = s
	}
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	block := []uint16{}
	for _, k := range keys {
		v, e := windows.UTF16FromString(entries[k])
		if e != nil {
			return nil, e
		}
		block = append(block, v...)
	}
	block = append(block, 0)
	if len(block) == 1 {
		block = append(block, 0)
	}
	return block, nil
}

// Start never executes the child before publish succeeds. All failure cleanup
// uses handles returned by CreateProcess, so PID reuse cannot redirect it.
func (j *Job) Start(spec Spec, publish func(platform.Identity) error) (*Process, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.handle == 0 {
		return nil, errors.New("owned job is closed")
	}
	return start(spec, publish, j.handle, false)
}

// StartIndependent is reserved for the recovery watchdog. It is published
// while suspended, and explicitly breaks away from the coordinator's outer
// job, if any. Windows refusing breakaway is a startup failure.
func StartIndependent(spec Spec, publish func(platform.Identity) error) (*Process, error) {
	return start(spec, publish, 0, true)
}
func start(spec Spec, publish func(platform.Identity) error, job windows.Handle, independent bool) (*Process, error) {
	if len(spec.Args) == 0 || !filepath.IsAbs(spec.Args[0]) || publish == nil {
		return nil, errors.New("owned job, absolute executable and publication callback required")
	}
	if independent {
		if err := independentJobPreflight(); err != nil {
			return nil, err
		}
	}
	app, e := windows.UTF16PtrFromString(spec.Args[0])
	if e != nil {
		return nil, e
	}
	line, e := windows.UTF16PtrFromString(windows.ComposeCommandLine(spec.Args))
	if e != nil {
		return nil, e
	}
	var cwd *uint16
	if spec.Directory != "" {
		cwd, e = windows.UTF16PtrFromString(spec.Directory)
		if e != nil {
			return nil, e
		}
	}
	block, e := environmentBlock(spec.Environment)
	if e != nil {
		return nil, e
	}
	var env *uint16
	if len(block) > 0 {
		env = &block[0]
	}
	startup := windows.StartupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	if independent {
		flags |= windows.CREATE_BREAKAWAY_FROM_JOB
	}
	if spec.NewConsole {
		flags |= windows.CREATE_NEW_CONSOLE
	} else {
		flags |= windows.CREATE_NO_WINDOW
	}
	inherit := false
	var inherited []windows.Handle
	defer func() {
		for _, h := range inherited {
			windows.CloseHandle(h)
		}
	}()
	files := []*os.File{spec.Stdin, spec.Stdout, spec.Stderr}
	if spec.Stdin != nil || spec.Stdout != nil || spec.Stderr != nil {
		for i, f := range files {
			if f == nil {
				return nil, errors.New("all three standard handles must be explicit")
			}
			var h windows.Handle
			e = windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(f.Fd()), windows.CurrentProcess(), &h, 0, true, windows.DUPLICATE_SAME_ACCESS)
			if e != nil {
				return nil, e
			}
			inherited = append(inherited, h)
			switch i {
			case 0:
				startup.StdInput = h
			case 1:
				startup.StdOutput = h
			case 2:
				startup.StdErr = h
			}
		}
		attrs, e := windows.NewProcThreadAttributeList(1)
		if e != nil {
			return nil, e
		}
		defer attrs.Delete()
		if e = attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inherited[0]), uintptr(len(inherited))*unsafe.Sizeof(inherited[0])); e != nil {
			return nil, e
		}
		startup.ProcThreadAttributeList = attrs.List()
		startup.Flags = windows.STARTF_USESTDHANDLES
		inherit = true
	}
	var info windows.ProcessInformation
	if e = windows.CreateProcess(app, line, nil, nil, inherit, flags, env, cwd, &startup.StartupInfo, &info); e != nil {
		return nil, fmt.Errorf("create suspended child: %w", e)
	}
	runtime.KeepAlive(block)
	defer windows.CloseHandle(info.Thread)
	success := false
	defer func() {
		if !success {
			_ = windows.TerminateProcess(info.Process, 1)
			_, _ = windows.WaitForSingleObject(info.Process, 5000)
			windows.CloseHandle(info.Process)
		}
	}()
	if job != 0 {
		if e = windows.AssignProcessToJobObject(job, info.Process); e != nil {
			return nil, e
		}
	}
	id, e := platform.ProcessIdentityFromHandle(info.Process, int(info.ProcessId))
	if e != nil {
		return nil, e
	}
	if id.PID == 0 || id.Birth == "" || id.OwnerSID == "" {
		return nil, errors.New("suspended child identity unavailable")
	}
	if e = publish(id); e != nil {
		return nil, e
	}
	if _, e = windows.ResumeThread(info.Thread); e != nil {
		return nil, e
	}
	success = true
	return &Process{Identity: id, handle: info.Process}, nil
}

// Wait owns the process handle; call it once, usually in a goroutine. Closing
// the owning job will terminate the child and unblock this wait.
func (p *Process) Wait() (uint32, error) {
	defer windows.CloseHandle(p.handle)
	if _, e := windows.WaitForSingleObject(p.handle, windows.INFINITE); e != nil {
		return 0, e
	}
	var code uint32
	e := windows.GetExitCodeProcess(p.handle, &code)
	return code, e
}
