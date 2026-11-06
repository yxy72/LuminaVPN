//go:build windows

package winservice

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

var lsaLogonData = windows.NewLazySystemDLL("secur32.dll").NewProc("LsaGetLogonSessionData")
var lsaFreeData = windows.NewLazySystemDLL("secur32.dll").NewProc("LsaFreeReturnBuffer")

func explicitTokenElevation(token windows.Token) (bool, error) {
	var value, needed uint32
	err := windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&value)), 4, &needed)
	return knownTokenElevation(value, needed, err)
}

type lsaUnicode struct {
	Length, Maximum uint16
	Buffer          *uint16
}

// Prefix through LogonTime, from the documented SECURITY_LOGON_SESSION_DATA.
type lsaLogonPrefix struct {
	Size                  uint32
	LogonID               windows.LUID
	User, Domain, Package lsaUnicode
	LogonType, Session    uint32
	SID                   *windows.SID
	LogonTime             int64
}

func kernelLogonEpoch(id windows.LUID, sid string, session uint32) (string, bool, error) {
	var pointer uintptr
	var pin runtime.Pinner
	pin.Pin(&id)
	pin.Pin(&pointer)
	defer pin.Unpin()
	status, _, _ := lsaLogonData.Call(uintptr(unsafe.Pointer(&id)), uintptr(unsafe.Pointer(&pointer)))
	if status != 0 || pointer == 0 {
		return "", false, errors.New("kernel logon identity unavailable")
	}
	defer lsaFreeData.Call(pointer)
	data := (*lsaLogonPrefix)(unsafe.Pointer(pointer))
	if data.Size < uint32(unsafe.Sizeof(lsaLogonPrefix{})) || data.LogonID != id || data.Session != session || data.SID == nil || data.SID.String() != sid || data.LogonTime <= 0 {
		return "", false, errors.New("kernel logon identity differs")
	}
	interactive := data.LogonType == 2 || data.LogonType == 7 || data.LogonType == 10 || data.LogonType == 11 || data.LogonType == 12
	return fmt.Sprintf("%016x", uint64(data.LogonTime)), interactive, nil
}
