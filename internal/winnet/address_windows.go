//go:build windows

package winnet

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func addressFromRow(row windows.MibUnicastIpAddressRow) (Address, error) {
	raw := *(*windows.RawSockaddrInet)(unsafe.Pointer(&row.Address))
	ip, e := address(raw)
	if e != nil {
		return Address{}, e
	}
	return Address{InterfaceIndex: row.InterfaceIndex, InterfaceLUID: row.InterfaceLuid, IP: ip, PrefixLength: row.OnLinkPrefixLength, PrefixOrigin: row.PrefixOrigin, SuffixOrigin: row.SuffixOrigin, ValidLifetime: row.ValidLifetime, PreferredLifetime: row.PreferredLifetime, SkipAsSource: row.SkipAsSource != 0, Created: uint64(row.CreationTimeStamp.HighDateTime)<<32 | uint64(row.CreationTimeStamp.LowDateTime)}, nil
}
func nativeUnicast(a Address) (windows.MibUnicastIpAddressRow, error) {
	if e := a.Validate(); e != nil {
		return windows.MibUnicastIpAddressRow{}, e
	}
	var row windows.MibUnicastIpAddressRow
	ipHelper.NewProc("InitializeUnicastIpAddressEntry").Call(uintptr(unsafe.Pointer(&row)))
	raw := nativeAddress(a.IP)
	row.Address = *(*windows.RawSockaddrInet6)(unsafe.Pointer(&raw))
	row.InterfaceIndex, row.InterfaceLuid = a.InterfaceIndex, a.InterfaceLUID
	row.PrefixOrigin, row.SuffixOrigin = a.PrefixOrigin, a.SuffixOrigin
	row.ValidLifetime, row.PreferredLifetime = a.ValidLifetime, a.PreferredLifetime
	row.OnLinkPrefixLength, row.SkipAsSource = 32, 0
	// Do not request optimistic DAD. The caller must await Preferred before
	// publishing this address as a usable VPN generation.
	row.DadState = windows.IpDadStateTentative
	return row, nil
}
func unicastRows() ([]windows.MibUnicastIpAddressRow, error) {
	var table *windows.MibUnicastIpAddressTable
	if e := windows.GetUnicastIpAddressTable(windows.AF_INET, &table); e != nil {
		return nil, e
	}
	if table == nil {
		return nil, errors.New("missing native address table")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	if table.NumEntries > 1<<20 {
		return nil, errors.New("native address table exceeded limit")
	}
	return append([]windows.MibUnicastIpAddressRow(nil), unsafe.Slice(&table.Table[0], table.NumEntries)...), nil
}
func Addresses() ([]Address, error) {
	rows, e := unicastRows()
	if e != nil {
		return nil, e
	}
	result := make([]Address, 0, len(rows))
	for _, row := range rows {
		a, e := addressFromRow(row)
		if e != nil {
			return nil, e
		}
		result = append(result, a)
	}
	return result, nil
}
func LookupAddress(wanted Address) (*Address, error) {
	if e := wanted.Validate(); e != nil {
		return nil, e
	}
	rows, e := Addresses()
	if e != nil {
		return nil, e
	}
	var found *Address
	for _, a := range rows {
		if !SameAddressKey(wanted, a) {
			continue
		}
		if found != nil {
			return nil, errors.New("ambiguous native address key")
		}
		copy := a
		found = &copy
	}
	return found, nil
}

// AddAddress refuses the same IP on every adapter, including tentative or
// deprecated addresses omitted by normal ready-adapter discovery.
func AddAddress(wanted Address) (Address, error) {
	row, e := nativeUnicast(wanted)
	if e != nil {
		return Address{}, e
	}
	all, e := Addresses()
	if e != nil {
		return Address{}, e
	}
	for _, a := range all {
		if a.IP == wanted.IP {
			return Address{}, errors.New("VPN address already exists")
		}
	}
	code, _, _ := ipHelper.NewProc("CreateUnicastIpAddressEntry").Call(uintptr(unsafe.Pointer(&row)))
	if code != 0 {
		return Address{}, fmt.Errorf("create VPN address: %w", windows.Errno(code))
	}
	actual, e := LookupAddress(wanted)
	if e != nil {
		return Address{}, e
	}
	if actual == nil || !OwnedAddressEqual(wanted, *actual) {
		return Address{}, errors.New("created VPN address differs; preserve journal")
	}
	return *actual, nil
}
func DeleteAddress(expected Address) error {
	row, e := nativeUnicast(expected)
	if e != nil {
		return e
	}
	actual, e := LookupAddress(expected)
	if e != nil || actual == nil {
		return e
	}
	if !OwnedAddressEqual(expected, *actual) {
		return errors.New("VPN address changed externally; deletion refused")
	}
	code, _, _ := ipHelper.NewProc("DeleteUnicastIpAddressEntry").Call(uintptr(unsafe.Pointer(&row)))
	if code != 0 && windows.Errno(code) != windows.ERROR_NOT_FOUND {
		return fmt.Errorf("delete VPN address: %w", windows.Errno(code))
	}
	return nil
}
func AddressReady(expected Address) error {
	if e := expected.Validate(); e != nil {
		return e
	}
	rows, e := unicastRows()
	if e != nil {
		return e
	}
	for _, row := range rows {
		a, e := addressFromRow(row)
		if e != nil {
			return e
		}
		if !SameAddressKey(expected, a) {
			continue
		}
		if !OwnedAddressEqual(expected, a) {
			return errors.New("VPN address identity changed")
		}
		if row.DadState != windows.IpDadStatePreferred {
			return errors.New("VPN address has not completed duplicate detection")
		}
		return nil
	}
	return errors.New("VPN address disappeared")
}

func adapterRow(a Adapter) (windows.MibIpInterfaceRow, error) {
	if a.Index == 0 || a.LUID == 0 || a.GUID == "" {
		return windows.MibIpInterfaceRow{}, errors.New("missing adapter identity")
	}
	items, e := Adapters()
	if e != nil {
		return windows.MibIpInterfaceRow{}, e
	}
	found := false
	for _, live := range items {
		if SameAdapter(a, live) {
			found = true
			break
		}
	}
	if !found {
		return windows.MibIpInterfaceRow{}, ErrAdapterAbsent
	}
	row := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: a.LUID, InterfaceIndex: a.Index}
	if e = windows.GetIpInterfaceEntry(&row); e != nil {
		return row, e
	}
	if row.InterfaceIndex != a.Index || row.InterfaceLuid != a.LUID {
		return row, errors.New("IP interface identity changed")
	}
	return row, nil
}
func MTU(a Adapter) (uint32, error) {
	row, e := adapterRow(a)
	return row.NlMtu, e
}

// SetMTU changes only this freshly read row's IPv4 MTU. Existing routing,
// forwarding, weak-host, metric and DAD settings are preserved.
func SetMTU(a Adapter, before, after uint32) error {
	if a.Hardware || a.Type != 53 || after < 576 || after > 65535 {
		return errors.New("invalid virtual adapter MTU")
	}
	row, e := adapterRow(a)
	if e != nil {
		return e
	}
	if row.NlMtu != before {
		return errors.New("MTU changed outside this run")
	}
	row.NlMtu = after
	row.SitePrefixLength = 0 // Required by SetIpInterfaceEntry for IPv4.
	code, _, _ := ipHelper.NewProc("SetIpInterfaceEntry").Call(uintptr(unsafe.Pointer(&row)))
	if code != 0 {
		return fmt.Errorf("set VPN MTU: %w", windows.Errno(code))
	}
	actual, e := MTU(a)
	if e != nil {
		return e
	}
	if actual != after {
		return errors.New("MTU readback differs; preserve journal")
	}
	return nil
}
