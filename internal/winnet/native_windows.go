//go:build windows

package winnet

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func Adapters() ([]Adapter, error) {
	size := uint32(16 << 10)
	for attempt := 0; attempt < 4; attempt++ {
		if size > 16<<20 {
			return nil, errors.New("adapter table exceeded limit")
		}
		buf := make([]byte, size)
		head := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		e := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_INCLUDE_ALL_INTERFACES, 0, head, &size)
		if errors.Is(e, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if errors.Is(e, windows.ERROR_NO_DATA) {
			return []Adapter{}, nil
		}
		if e != nil {
			return nil, e
		}
		var result []Adapter
		for p := head; p != nil; p = p.Next {
			row := windows.MibIfRow2{InterfaceLuid: p.Luid, InterfaceIndex: p.IfIndex}
			if e := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row); e != nil {
				return nil, e
			}
			if row.InterfaceLuid != p.Luid || row.InterfaceIndex != p.IfIndex {
				return nil, errors.New("adapter identity changed during discovery")
			}
			a := Adapter{Index: p.IfIndex, LUID: p.Luid, Name: windows.UTF16PtrToString(p.FriendlyName), GUID: row.InterfaceGuid.String(), Type: p.IfType, Up: p.OperStatus == windows.IfOperStatusUp && row.OperStatus == windows.IfOperStatusUp, Hardware: row.InterfaceAndOperStatusFlags&1 != 0, Metric: p.Ipv4Metric}
			for u := p.FirstUnicastAddress; u != nil; u = u.Next {
				ip, ok := netip.AddrFromSlice(u.Address.IP())
				if ok && ip.Is4() && u.DadState == 4 && u.ValidLifetime > 0 {
					a.Addresses = append(a.Addresses, ip.String())
				}
			}
			for d := p.FirstDnsServerAddress; d != nil; d = d.Next {
				ip, ok := netip.AddrFromSlice(d.Address.IP())
				if ok && ip.Is4() {
					a.DNS = append(a.DNS, ip.String())
				}
			}
			result = append(result, a)
		}
		runtime.KeepAlive(buf)
		return result, nil
	}
	return nil, errors.New("adapter table changed repeatedly")
}

func address(a windows.RawSockaddrInet) (string, error) {
	if a.Family != windows.AF_INET {
		return "", errors.New("expected IPv4 route")
	}
	v := (*windows.RawSockaddrInet4)(unsafe.Pointer(&a))
	return netip.AddrFrom4(v.Addr).String(), nil
}
func nativeAddress(s string) windows.RawSockaddrInet {
	a := netip.MustParseAddr(s)
	var raw windows.RawSockaddrInet
	v := (*windows.RawSockaddrInet4)(unsafe.Pointer(&raw))
	v.Family = windows.AF_INET
	v.Addr = a.As4()
	return raw
}
func routeFromRow(r windows.MibIpForwardRow2) (Route, error) {
	ip, e := address(r.DestinationPrefix.Prefix)
	if e != nil || r.DestinationPrefix.PrefixLength > 32 {
		return Route{}, errors.New("invalid native route prefix")
	}
	h, e := address(r.NextHop)
	if e != nil {
		return Route{}, e
	}
	p := netip.PrefixFrom(netip.MustParseAddr(ip), int(r.DestinationPrefix.PrefixLength)).Masked()
	return Route{InterfaceIndex: r.InterfaceIndex, InterfaceLUID: r.InterfaceLuid, Prefix: p.String(), NextHop: h, Metric: r.Metric, Protocol: r.Protocol, Origin: r.Origin, ValidLifetime: r.ValidLifetime, PreferredLifetime: r.PreferredLifetime, SitePrefixLength: r.SitePrefixLength, Loopback: r.Loopback != 0, AutoConfigure: r.AutoconfigureAddress != 0, Publish: r.Publish != 0, Immortal: r.Immortal != 0}, nil
}
func Routes() ([]Route, error) {
	var table *windows.MibIpForwardTable2
	if e := windows.GetIpForwardTable2(windows.AF_INET, &table); e != nil {
		return nil, e
	}
	if table == nil {
		return nil, errors.New("missing route table")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	if table.NumEntries > 1<<20 {
		return nil, errors.New("route table exceeded limit")
	}
	result := make([]Route, 0, table.NumEntries)
	for _, row := range table.Rows() {
		r, e := routeFromRow(row)
		if e != nil {
			return nil, e
		}
		result = append(result, r)
	}
	return result, nil
}

func Discover() (Physical, error) {
	a, e := Adapters()
	if e != nil {
		return Physical{}, e
	}
	r, e := Routes()
	if e != nil {
		return Physical{}, e
	}
	n, e := SelectPhysical(a, r)
	if e != nil {
		return n, e
	}
	return n, ValidateAdapter(n.Adapter, n.Address)
}

// ValidateAdapter checks LUID as well as index, which Windows may reuse after
// an adapter is removed. Address validation is required for a VPN generation.
func ValidateAdapter(expected Adapter, ip string) error {
	if expected.Index == 0 || expected.LUID == 0 {
		return errors.New("missing adapter identity")
	}
	items, e := Adapters()
	if e != nil {
		return e
	}
	for _, a := range items {
		if a.Index != expected.Index || a.LUID != expected.LUID || a.GUID != expected.GUID || a.Name != expected.Name || !a.Up {
			continue
		}
		if ip == "" {
			return nil
		}
		for _, v := range a.Addresses {
			if v == ip {
				return nil
			}
		}
	}
	return errors.New("adapter generation is unavailable")
}

var ipHelper = windows.NewLazySystemDLL("iphlpapi.dll")

func nativeRow(r Route) (windows.MibIpForwardRow2, error) {
	if e := managedRoute(r); e != nil {
		return windows.MibIpForwardRow2{}, e
	}
	var row windows.MibIpForwardRow2
	ipHelper.NewProc("InitializeIpForwardEntry").Call(uintptr(unsafe.Pointer(&row)))
	p := netip.MustParsePrefix(r.Prefix)
	row.InterfaceLuid = r.InterfaceLUID
	row.InterfaceIndex = r.InterfaceIndex
	row.DestinationPrefix = windows.IpAddressPrefix{Prefix: nativeAddress(p.Addr().String()), PrefixLength: uint8(p.Bits())}
	row.NextHop = nativeAddress(r.NextHop)
	row.Metric = r.Metric
	row.Protocol = r.Protocol
	row.ValidLifetime = r.ValidLifetime
	row.PreferredLifetime = r.PreferredLifetime
	// InitializeIpForwardEntry uses 0xff sentinels for optional fields. Do not
	// publish those sentinels or rely on kernel defaults for journal ownership.
	row.SitePrefixLength = r.SitePrefixLength
	row.Origin = r.Origin
	row.Loopback = 0
	row.AutoconfigureAddress = 0
	row.Publish = 0
	row.Immortal = 0
	return row, nil
}

func Lookup(r Route) (*Route, error) {
	if e := managedRoute(r); e != nil {
		return nil, e
	}
	// Enumerating proves absence even after reboot, when an old LUID can make
	// GetIpForwardEntry2 fail before looking up the route itself.
	rows, e := Routes()
	if e != nil {
		return nil, e
	}
	var found *Route
	for _, row := range rows {
		if !SameKey(r, row) {
			continue
		}
		if found != nil {
			return nil, errors.New("ambiguous native route key")
		}
		copy := row
		found = &copy
	}
	return found, nil
}

// Add creates only a new, exact route; existing routes are never updated. Its
// caller must durably record an absent-before-add intent before invoking it.
func Add(r Route) (Route, error) {
	row, e := nativeRow(r)
	if e != nil {
		return Route{}, e
	}
	actual, e := Lookup(r)
	if e != nil {
		return Route{}, e
	}
	if actual != nil {
		return Route{}, errors.New("route already exists")
	}
	code, _, _ := ipHelper.NewProc("CreateIpForwardEntry2").Call(uintptr(unsafe.Pointer(&row)))
	if code != 0 {
		return Route{}, fmt.Errorf("create native route: %w", windows.Errno(code))
	}
	actual, e = Lookup(r)
	if e != nil {
		return Route{}, e
	}
	if actual == nil || !OwnedEqual(r, *actual) {
		return Route{}, errors.New("created route readback differs; preserve recovery journal")
	}
	return *actual, nil
}

// Delete removes an exact owned record only after a fresh native readback.
// Absence is success. Changed attributes are left for manual recovery.
func Delete(expected Route) error {
	row, e := nativeRow(expected)
	if e != nil {
		return e
	}
	actual, e := Lookup(expected)
	if e != nil || actual == nil {
		return e
	}
	if !OwnedEqual(expected, *actual) {
		return errors.New("route changed outside this run; refusing deletion")
	}
	code, _, _ := ipHelper.NewProc("DeleteIpForwardEntry2").Call(uintptr(unsafe.Pointer(&row)))
	if code != 0 && windows.Errno(code) != windows.ERROR_NOT_FOUND {
		return fmt.Errorf("delete native route: %w", windows.Errno(code))
	}
	return nil
}
