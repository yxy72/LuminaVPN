//go:build windows

package winservice

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var getShellWindow = windows.NewLazySystemDLL("user32.dll").NewProc("GetShellWindow")
var getWindowThreadProcessID = windows.NewLazySystemDLL("user32.dll").NewProc("GetWindowThreadProcessId")

func enrollmentTokenFacts(token windows.Token) (EnrollmentFacts, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return EnrollmentFacts{}, err
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return EnrollmentFacts{}, err
	}
	var logon string
	for _, group := range groups.AllGroups() {
		if group.Attributes&0xC0000000 == 0xC0000000 && group.Attributes&windows.SE_GROUP_ENABLED != 0 && group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			if logon != "" {
				return EnrollmentFacts{}, errors.New("multiple enabled logon identities")
			}
			logon = group.Sid.String()
		}
	}
	var statistics tokenStatistics
	var needed uint32
	if err = windows.GetTokenInformation(token, windows.TokenStatistics, (*byte)(unsafe.Pointer(&statistics)), uint32(unsafe.Sizeof(statistics)), &needed); err != nil {
		return EnrollmentFacts{}, err
	}
	if needed != uint32(unsafe.Sizeof(statistics)) {
		return EnrollmentFacts{}, errors.New("token statistics observation unknown")
	}
	var session, elevationType uint32
	if err = windows.GetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4, &needed); err != nil {
		return EnrollmentFacts{}, err
	}
	if needed != 4 {
		return EnrollmentFacts{}, errors.New("token session observation unknown")
	}
	if err = windows.GetTokenInformation(token, windows.TokenElevationType, (*byte)(unsafe.Pointer(&elevationType)), 4, &needed); err != nil {
		return EnrollmentFacts{}, err
	}
	if needed != 4 || elevationType < 1 || elevationType > 3 {
		return EnrollmentFacts{}, errors.New("token elevation type observation unknown")
	}
	epoch, interactive, err := kernelLogonEpoch(statistics.AuthenticationID, user.User.Sid.String(), session)
	if err != nil {
		return EnrollmentFacts{}, err
	}
	elevated, err := explicitTokenElevation(token)
	if err != nil {
		return EnrollmentFacts{}, err
	}
	// TOKEN_ELEVATION_TYPE: Default=1, Full=2, Limited=3 (winnt.h).
	return EnrollmentFacts{SID: user.User.Sid.String(), LogonSID: logon, AuthenticationID: fmt.Sprintf("%08x-%08x", statistics.AuthenticationID.HighPart, statistics.AuthenticationID.LowPart), SessionID: session, Primary: statistics.TokenType == windows.TokenPrimary, Elevated: elevated, Limited: elevationType == 3, LogonEpoch: epoch, Interactive: interactive}, nil
}
func captureInstallerEnrollment() (Binding, error) {
	process := windows.GetCurrentProcessToken()
	full, err := enrollmentTokenFacts(process)
	if err != nil {
		return Binding{}, err
	}
	linked, err := process.GetLinkedToken()
	if err != nil {
		return Binding{}, errors.New("linked ordinary user token required")
	}
	defer linked.Close()
	limited, err := enrollmentTokenFacts(linked)
	if err != nil {
		return Binding{}, err
	}
	window, _, _ := getShellWindow.Call()
	if window == 0 {
		return Binding{}, errors.New("interactive shell identity unavailable")
	}
	var pid uint32
	_, _, _ = getWindowThreadProcessID.Call(window, uintptr(unsafe.Pointer(&pid)))
	runtime.KeepAlive(&pid)
	if pid == 0 {
		return Binding{}, errors.New("interactive shell process unavailable")
	}
	shellProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return Binding{}, err
	}
	defer windows.CloseHandle(shellProcess)
	var shellToken windows.Token
	if err = windows.OpenProcessToken(shellProcess, windows.TOKEN_QUERY, &shellToken); err != nil {
		return Binding{}, err
	}
	defer shellToken.Close()
	shell, err := enrollmentTokenFacts(shellToken)
	if err != nil {
		return Binding{}, err
	}
	profile, err := linked.GetUserProfileDirectory()
	if err != nil || !filepath.IsAbs(profile) {
		return Binding{}, errors.New("ordinary native profile unavailable")
	}
	// Native userenv path, not the elevated process environment or RPC input.
	return verifiedEnrollment(full, limited, shell, localProfileID(filepath.Join(profile, ".netlaunch")))
}
