//go:build windows

package platform

import (
	"errors"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Process reads all identity fields through one native handle. Command lines
// are intentionally not collected: VPN credentials must not enter the journal.
func Process(pid int) (Identity, error) {
	if pid < 2 || uint64(pid) > uint64(^uint32(0)) {
		return Identity{}, errors.New("invalid process id")
	}
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if errors.Is(e, windows.ERROR_INVALID_PARAMETER) {
		return Identity{}, nil
	}
	if e != nil {
		return Identity{}, e
	}
	defer windows.CloseHandle(h)
	return ProcessIdentityFromHandle(h, pid)
}

// ProcessIdentityFromHandle keeps identity queries tied to a held handle.
func ProcessIdentityFromHandle(h windows.Handle, pid int) (Identity, error) {
	var code uint32
	if e := windows.GetExitCodeProcess(h, &code); e != nil {
		return Identity{}, e
	}
	if code != 259 {
		return Identity{}, nil
	}
	var birth, exit, kernel, user windows.Filetime
	if e := windows.GetProcessTimes(h, &birth, &exit, &kernel, &user); e != nil {
		return Identity{}, e
	}
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if e := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); e != nil {
		return Identity{}, e
	}
	var token windows.Token
	if e := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); e != nil {
		return Identity{}, e
	}
	defer token.Close()
	u, e := token.GetTokenUser()
	if e != nil {
		return Identity{}, e
	}
	if u.User.Sid == nil {
		return Identity{}, errors.New("process owner missing")
	}
	return Identity{PID: pid, Birth: strconv.FormatUint(uint64(birth.HighDateTime)<<32|uint64(birth.LowDateTime), 16), Executable: windows.UTF16ToString(buf[:size]), OwnerSID: u.User.Sid.String()}, nil
}

// StopIdentity cannot kill a recycled PID: validation and termination use the
// same process handle. Only a fully journaled identity may be supplied.
func StopIdentity(expected Identity) error {
	if expected.PID < 2 || uint64(expected.PID) > uint64(^uint32(0)) || expected.Birth == "" || expected.Executable == "" || expected.OwnerSID == "" {
		return errors.New("incomplete process identity")
	}
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE, false, uint32(expected.PID))
	if errors.Is(e, windows.ERROR_INVALID_PARAMETER) {
		return nil
	}
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	actual, e := ProcessIdentityFromHandle(h, expected.PID)
	if e != nil || actual.PID == 0 {
		return e
	}
	if actual.Birth != expected.Birth || actual.OwnerSID != expected.OwnerSID || !strings.EqualFold(actual.Executable, expected.Executable) {
		return errors.New("process identity changed; refusing termination")
	}
	return windows.TerminateProcess(h, 1)
}

func foreignOpenConnect() (bool, error) {
	h, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return false, e
	}
	defer windows.CloseHandle(h)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	e = windows.Process32First(h, &entry)
	for e == nil {
		if strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), "openconnect.exe") {
			return true, nil
		}
		e = windows.Process32Next(h, &entry)
	}
	if errors.Is(e, windows.ERROR_NO_MORE_FILES) {
		return false, nil
	}
	return false, e
}
