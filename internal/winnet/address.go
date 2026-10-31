package winnet

import "errors"

// Address contains writable IPv4 attributes and the kernel creation stamp.
// DAD state is deliberately separate: an address can be owned but not ready.
type Address struct {
	InterfaceIndex    uint32 `json:"interface_index"`
	InterfaceLUID     uint64 `json:"interface_luid"`
	IP                string `json:"ip"`
	PrefixLength      uint8  `json:"prefix_length"`
	PrefixOrigin      uint32 `json:"prefix_origin"`
	SuffixOrigin      uint32 `json:"suffix_origin"`
	ValidLifetime     uint32 `json:"valid_lifetime"`
	PreferredLifetime uint32 `json:"preferred_lifetime"`
	SkipAsSource      bool   `json:"skip_as_source"`
	Created           uint64 `json:"created,omitempty"`
}

var ErrAdapterAbsent = errors.New("adapter is absent")
var ErrIPInterfaceAbsent = errors.New("IPv4 interface row is absent")

func (a Address) Validate() error {
	if a.InterfaceIndex == 0 || a.InterfaceLUID == 0 || !usableIPv4(a.IP) || a.PrefixLength != 32 || a.PrefixOrigin != 1 || a.SuffixOrigin != 1 || a.ValidLifetime != ^uint32(0) || a.PreferredLifetime != ^uint32(0) || a.SkipAsSource {
		return errors.New("managed VPN address requires manual unicast IPv4 /32 with infinite lifetimes")
	}
	return nil
}
func NewVPNAddress(a Adapter, ip string) (Address, error) {
	if a.Hardware || a.Type != 53 || a.Index == 0 || a.LUID == 0 || a.GUID == "" {
		return Address{}, errors.New("owned virtual tunnel adapter required")
	}
	v := Address{InterfaceIndex: a.Index, InterfaceLUID: a.LUID, IP: ip, PrefixLength: 32, PrefixOrigin: 1, SuffixOrigin: 1, ValidLifetime: ^uint32(0), PreferredLifetime: ^uint32(0)}
	return v, v.Validate()
}
func SameAddressKey(a, b Address) bool {
	return a.InterfaceIndex == b.InterfaceIndex && a.InterfaceLUID == b.InterfaceLUID && a.IP == b.IP
}
func SameAddressAttributes(a, b Address) bool {
	a.Created, b.Created = 0, 0
	return a == b
}
func OwnedAddressEqual(expected, actual Address) bool {
	return SameAddressAttributes(expected, actual) && (expected.Created == 0 || expected.Created == actual.Created)
}
func ValidVPNMTU(mtu uint32) bool { return mtu >= 576 && mtu <= 1500 }
func SameAdapter(a, b Adapter) bool {
	return a.Index != 0 && a.LUID != 0 && a.GUID != "" && a.Index == b.Index && a.LUID == b.LUID && a.GUID == b.GUID
}
