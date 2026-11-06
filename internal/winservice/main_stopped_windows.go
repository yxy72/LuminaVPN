//go:build windows

package winservice

import (
	"errors"
	"golang.org/x/sys/windows"
	"unsafe"
)

// RequireMainServiceStopped is an independent fixed-SCM observation used by
// the recovery role, never a claim accepted from a request or old manifest.
func RequireMainServiceStopped() error {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(manager)
	name, _ := windows.UTF16PtrFromString(ServiceName)
	service, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if err = windows.QueryServiceStatusEx(service, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed); err != nil {
		return err
	}
	if status.CurrentState != windows.SERVICE_STOPPED || status.ProcessId != 0 {
		return errors.New("current main service is live or unknown")
	}
	return nil
}
