//go:build windows

package winnet

import (
	"errors"
	"golang.org/x/sys/windows"
	"strconv"
	"unsafe"
)

// BootID reads the kernel boot timestamp. Wall-clock estimates based on uptime
// are unsuitable as durable identity because successive estimates can differ.
func BootID() (string, error) {
	var data struct {
		BootTime, CurrentTime, TimeZoneBias int64
		TimeZoneID, Reserved                uint32
		BootBias, SleepBias                 uint64
	}
	var n uint32
	status, _, _ := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQuerySystemInformation").Call(3, uintptr(unsafe.Pointer(&data)), unsafe.Sizeof(data), uintptr(unsafe.Pointer(&n)))
	if int32(status) < 0 {
		return "", windows.NTStatus(status)
	}
	if n < 8 || data.BootTime <= 0 {
		return "", errors.New("missing native boot identity")
	}
	return strconv.FormatInt(data.BootTime, 16), nil
}
