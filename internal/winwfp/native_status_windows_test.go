//go:build windows

package winwfp

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// These are pure return-register fixtures; they never call WFP or load a DLL.
func TestWFPCallResultNormalizesDWORDBeforeSuccessAndErrorChecks(t *testing.T) {
	const api = "FwpmFilterGetByKey0"
	statuses := []uint32{0, 0x80320003, 0x80320007, 5, 0x80320009}
	upperBits := []struct {
		name string
		bits uint64
	}{
		{name: "zero extended"},
		{name: "sign extended", bits: 0xffffffff00000000},
		{name: "undefined high bits", bits: 0x13579bdf00000000},
	}
	for _, status := range statuses {
		for _, upper := range upperBits {
			t.Run(fmt.Sprintf("%08x/%s", status, upper.name), func(t *testing.T) {
				raw := uintptr(upper.bits | uint64(status))
				err := wfpCallResult(api, raw)
				if status == 0 {
					if err != nil {
						t.Fatal("undefined upper bits turned a successful DWORD into failure", err)
					}
					return
				}
				if err == nil || !strings.HasPrefix(err.Error(), api+": ") ||
					!strings.Contains(err.Error(), fmt.Sprintf("status=0x%08x", status)) ||
					!strings.Contains(err.Error(), fmt.Sprintf("raw=0x%016x", raw)) {
					t.Fatal("lost API name or native status/register diagnostics", err)
				}
				want := windows.Errno(status)
				var actual windows.Errno
				if !errors.Is(err, want) || !errors.As(err, &actual) || actual != want {
					t.Fatal("DWORD status was not preserved as an unwrap-compatible Errno", actual, err)
				}
				for _, other := range statuses {
					if other != status && errors.Is(err, windows.Errno(other)) {
						t.Fatal("unrelated native status was treated as the same error", other, err)
					}
				}
			})
		}
	}
}
