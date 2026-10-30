//go:build windows

package engine

import (
	"errors"
	"golang.org/x/sys/windows"
	"netlaunch/internal/securefile"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"
)

// SHELLEXECUTEINFOW; Windows amd64 is the MVP target.
type shellExecuteInfo struct {
	Size, Mask                        uint32
	Window                            windows.Handle
	Verb, File, Parameters, Directory *uint16
	Show                              int32
	Instance                          windows.Handle
	IDList                            uintptr
	Class                             *uint16
	ClassKey                          windows.Handle
	HotKey                            uint32
	Icon                              windows.Handle
	Process                           windows.Handle
}

func Launch(action, run string) error {
	if action != "serve" && action != "recover" {
		return errors.New("invalid administrator action")
	}
	m, e := ReadManifest(run)
	if e != nil {
		return e
	}
	executable := m.Executable
	if executable != filepath.Join(run, "netlaunch.exe") {
		return errors.New("invalid staged Windows executable")
	}
	if e = securefile.CheckPrivate(executable, false); e != nil {
		return e
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, e := windows.UTF16PtrFromString(executable)
	if e != nil {
		return e
	}
	params, e := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{"_" + action, "--run", run}))
	if e != nil {
		return e
	}
	cwd, e := windows.UTF16PtrFromString(filepath.Dir(executable))
	if e != nil {
		return e
	}
	info := shellExecuteInfo{Mask: 0x40 | 0x100, Verb: verb, File: file, Parameters: params, Directory: cwd, Show: 0}
	info.Size = uint32(unsafe.Sizeof(info))
	ok, _, callErr := windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW").Call(uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive([]any{verb, file, params, cwd})
	if ok == 0 {
		return callErr
	}
	if info.Process == 0 {
		return errors.New("administrator launch has no process handle")
	}
	defer windows.CloseHandle(info.Process)
	if action == "serve" {
		return nil
	}
	// ShellExecuteEx is asynchronous; down must not read a stale status before
	// the elevated recovery finishes. The actual process handle is authoritative.
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		result, e := windows.WaitForSingleObject(info.Process, 1000)
		if e != nil {
			return e
		}
		if result == windows.WAIT_OBJECT_0 {
			var code uint32
			if e = windows.GetExitCodeProcess(info.Process, &code); e != nil {
				return e
			}
			if code != 0 {
				return errors.New("administrator recovery did not complete")
			}
			return nil
		}
	}
	return errors.New("recovery still running; inspect status and preserve the run")
}
func Internal(action, run string) error {
	if e := securefile.RequireAdmin(); e != nil {
		return e
	}
	if action == "hook" && run == "" {
		run = os.Getenv("NETLAUNCH_HOOK_RUN")
	}
	switch action {
	case "serve":
		return serve(run)
	case "run":
		return runFrozen(run)
	case "watch":
		return watch(run)
	case "recover":
		return recoverRun(run, "explicit_recovery")
	case "hook":
		return hook(run)
	}
	return errors.New("unknown internal action")
}
func ChildMain(string, int) error {
	return errors.New("Windows uses suspended native child publication")
}

// recover uses the immutable administrator executable after initialization.
// A public launcher may be removed without invalidating the saved journal.
func frozenSelf(run string) string { return filepath.Join(private(run), "netlaunch.exe") }
