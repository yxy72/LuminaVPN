//go:build windows

package winservice

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
	"netlaunch/internal/winprofile"
)

var getShellWindow = windows.NewLazySystemDLL("user32.dll").NewProc("GetShellWindow")
var getWindowThreadProcessID = windows.NewLazySystemDLL("user32.dll").NewProc("GetWindowThreadProcessId")

func enrollmentTokenFacts(token windows.Token) (EnrollmentFacts, error) {
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		if err == nil {
			err = errors.New("token user observation unknown")
		}
		return EnrollmentFacts{}, err
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return EnrollmentFacts{}, err
	}
	var logon string
	var enabledAdmin, adminDenyOnly bool
	for _, group := range groups.AllGroups() {
		if group.Sid.String() == "S-1-5-32-544" {
			enabledAdmin = group.Attributes&windows.SE_GROUP_ENABLED != 0
			adminDenyOnly = group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0
		}
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
	err = windows.GetTokenInformation(token, windows.TokenElevationType, (*byte)(unsafe.Pointer(&elevationType)), 4, &needed)
	if elevationType, err = knownTokenElevationType(elevationType, needed, err); err != nil {
		return EnrollmentFacts{}, err
	}
	epoch, interactive, err := kernelLogonEpoch(statistics.AuthenticationID, user.User.Sid.String(), session)
	if err != nil {
		return EnrollmentFacts{}, err
	}
	elevated, err := explicitTokenElevation(token)
	if err != nil {
		return EnrollmentFacts{}, err
	}
	profile, err := winprofile.PathForToken(token)
	if err != nil {
		return EnrollmentFacts{}, errors.New("OS user profile unavailable")
	}
	return EnrollmentFacts{SID: user.User.Sid.String(), LogonSID: logon, AuthenticationID: fmt.Sprintf("%08x-%08x", statistics.AuthenticationID.HighPart, statistics.AuthenticationID.LowPart), SessionID: session, TokenType: statistics.TokenType, ImpersonationLevel: statistics.ImpersonationLevel, ElevationType: elevationType, Elevated: elevated, EnabledAdmin: enabledAdmin, AdminDenyOnly: adminDenyOnly, LogonEpoch: epoch, Interactive: interactive, ProfileID: localProfileID(profile)}, nil
}

// VerifyCurrentInteractiveUser checks the real process token used by a fixed
// user worker. It never substitutes a thread token or changes token elevation.
func VerifyCurrentInteractiveUser() error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	facts, err := enrollmentTokenFacts(token)
	if err != nil {
		return err
	}
	return requireDesktopProcess(facts)
}

func captureInstallerEnrollment() (Binding, error) {
	var process windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &process); err != nil {
		return Binding{}, err
	}
	defer process.Close()
	full, err := enrollmentTokenFacts(process)
	if err != nil {
		return Binding{}, err
	}
	var limited EnrollmentFacts
	if full.ElevationType == tokenElevationFull {
		linked, err := process.GetLinkedToken()
		if err != nil {
			return Binding{}, errors.New("linked desktop user token required")
		}
		defer linked.Close()
		limited, err = enrollmentTokenFacts(linked)
		if err != nil {
			return Binding{}, err
		}
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
	return verifiedEnrollment(full, limited, shell)
}
