//go:build windows

package usersession

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

type dataBlob struct {
	Size uint32
	Data *byte
}
type nativeProtector struct{}

var crypt = windows.NewLazySystemDLL("crypt32.dll")
var localFree = windows.NewLazySystemDLL("kernel32.dll").NewProc("LocalFree")

func dpapi(name string, input, entropy []byte) ([]byte, error) {
	if len(input) == 0 || len(entropy) == 0 {
		return nil, errors.New("empty DPAPI data")
	}
	in := dataBlob{uint32(len(input)), &input[0]}
	ent := dataBlob{uint32(len(entropy)), &entropy[0]}
	var out dataBlob
	p := crypt.NewProc(name)
	if err := p.Find(); err != nil {
		return nil, err
	}
	// CRYPTPROTECT_UI_FORBIDDEN only. Never CRYPTPROTECT_LOCAL_MACHINE.
	ok, _, err := p.Call(uintptr(unsafe.Pointer(&in)), 0, uintptr(unsafe.Pointer(&ent)), 0, 0, 1, uintptr(unsafe.Pointer(&out)))
	runtime.KeepAlive(input)
	runtime.KeepAlive(entropy)
	if ok == 0 {
		if err != nil && err != windows.ERROR_SUCCESS {
			return nil, err
		}
		return nil, errors.New("DPAPI operation failed")
	}
	if out.Data == nil {
		return nil, errors.New("DPAPI returned no data")
	}
	defer localFree.Call(uintptr(unsafe.Pointer(out.Data)))
	if out.Size == 0 || out.Size > 512<<10 {
		return nil, errors.New("invalid DPAPI output length")
	}
	view := unsafe.Slice(out.Data, out.Size)
	result := append([]byte(nil), view...)
	clear(view)
	return result, nil
}
func (nativeProtector) Protect(p, e []byte) ([]byte, error) { return dpapi("CryptProtectData", p, e) }
func (nativeProtector) Unprotect(p, e []byte) ([]byte, error) {
	return dpapi("CryptUnprotectData", p, e)
}
