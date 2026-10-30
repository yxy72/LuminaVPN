//go:build windows

package winnet

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

// DNS_INTERFACE_SETTINGS v1, as declared in netioapi.h. GUID parameters use
// the Windows amd64 by-value aggregate convention (a temporary pointer).
// https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getinterfacednssettings
type dnsInterfaceSettings struct {
	Version             uint32
	Flags               uint64
	Domain              *uint16
	NameServer          *uint16
	SearchList          *uint16
	RegistrationEnabled uint32
	RegisterAdapterName uint32
	EnableLLMNR         uint32
	QueryAdapterName    uint32
	ProfileNameServer   *uint16
}

func dnsGUID(a Adapter) (windows.GUID, error) {
	if runtime.GOARCH != "amd64" {
		return windows.GUID{}, errors.New("native DNS currently requires Windows amd64")
	}
	if a.Index == 0 || a.LUID == 0 {
		return windows.GUID{}, errors.New("missing DNS adapter identity")
	}
	guid, e := windows.GUIDFromString(a.GUID)
	if e != nil {
		return guid, e
	}
	row := windows.MibIfRow2{InterfaceLuid: a.LUID, InterfaceIndex: a.Index}
	if e = windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row); e != nil {
		return guid, e
	}
	if row.InterfaceLuid != a.LUID || row.InterfaceIndex != a.Index || row.InterfaceGuid != guid {
		return guid, errors.New("DNS adapter identity changed")
	}
	return guid, nil
}

func ConfiguredDNS(a Adapter) (DNSSettings, error) {
	guid, e := dnsGUID(a)
	if e != nil {
		return DNSSettings{}, e
	}
	get := ipHelper.NewProc("GetInterfaceDnsSettings")
	free := ipHelper.NewProc("FreeInterfaceDnsSettings")
	if e = get.Find(); e != nil {
		return DNSSettings{}, e
	}
	if e = free.Find(); e != nil {
		return DNSSettings{}, e
	}
	native := dnsInterfaceSettings{Version: 1}
	code, _, _ := get.Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&native)))
	if code != 0 {
		return DNSSettings{}, fmt.Errorf("read configured DNS: %w", windows.Errno(code))
	}
	defer free.Call(uintptr(unsafe.Pointer(&native)))
	// Extended settings require a wider snapshot than this MVP can restore.
	if native.Flags&0x3000 != 0 {
		return DNSSettings{}, errors.New("configured DoH requires extended DNS recovery support")
	}
	d := DNSSettings{windows.UTF16PtrToString(native.NameServer), windows.UTF16PtrToString(native.ProfileNameServer)}
	return d, d.Validate()
}

// SetConfiguredDNS changes only the static IPv4 server list. Its caller must
// first persist Before/After and re-read Before. Profile DNS is never altered.
func SetConfiguredDNS(a Adapter, desired DNSSettings) error {
	if e := desired.Validate(); e != nil {
		return e
	}
	guid, e := dnsGUID(a)
	if e != nil {
		return e
	}
	current, e := ConfiguredDNS(a)
	if e != nil {
		return e
	}
	if !SameDNS(DNSSettings{ProfileNameServers: current.ProfileNameServers}, DNSSettings{ProfileNameServers: desired.ProfileNameServers}) {
		return errors.New("profile DNS changed outside this run")
	}
	value, e := windows.UTF16PtrFromString(desired.NameServers)
	if e != nil {
		return e
	}
	native := dnsInterfaceSettings{Version: 1, Flags: 2, NameServer: value}
	set := ipHelper.NewProc("SetInterfaceDnsSettings")
	if e = set.Find(); e != nil {
		return e
	}
	code, _, _ := set.Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&native)))
	runtime.KeepAlive(value)
	if code != 0 {
		return fmt.Errorf("set configured DNS: %w", windows.Errno(code))
	}
	actual, e := ConfiguredDNS(a)
	if e != nil {
		return e
	}
	if !SameDNS(desired, actual) {
		return errors.New("configured DNS readback differs; preserve recovery journal")
	}
	return nil
}
