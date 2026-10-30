//go:build windows

package runtimebundle

import (
	"errors"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Resolve the verified library's exports without calling driver/adapter APIs.
func checkLibraries(root string) ([]LibraryCheck, error) {
	result := []LibraryCheck{{Component: "wintun.dll", Status: "load_failed", Scope: "library_load_and_exports_only"}}
	handle, e := windows.LoadLibraryEx(filepath.Join(root, "bin", "wintun.dll"), 0,
		windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if e != nil {
		return result, errors.New("verified Wintun library could not load; inspect the operating system security log")
	}
	defer windows.FreeLibrary(handle)
	for _, name := range []string{"WintunCreateAdapter", "WintunOpenAdapter", "WintunCloseAdapter", "WintunGetAdapterLUID", "WintunStartSession", "WintunEndSession", "WintunReceivePacket", "WintunReleaseReceivePacket", "WintunAllocateSendPacket", "WintunSendPacket", "WintunGetReadWaitEvent"} {
		if _, e := windows.GetProcAddress(handle, name); e != nil {
			result[0].Status = "missing_export"
			return result, errors.New("verified Wintun library is missing a required export")
		}
	}
	result[0].Status = "pass"
	return result, nil
}
