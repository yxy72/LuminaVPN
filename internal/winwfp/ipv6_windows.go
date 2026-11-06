//go:build windows

package winwfp

import (
	"errors"
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

type provider struct {
	Key         windows.GUID
	Display     display
	Flags       uint32
	Data        blob
	ServiceName *uint16
}
type ipv6Allocation struct {
	name       []uint16
	marker     []byte
	provider   provider
	sub        sublayer
	filters    [2]filter
	conditions [1]condition
}

// WinSDK fwpmu.h: the packet send path and the IPv6 forwarding path. No
// inbound local-delivery rule is installed. These filters do not depend on an
// app, interface, protocol, current connection or optional company channel.
var outboundPacketV6 = mustGUID("{a3b3ab6b-3564-488c-9117-f34e82142763}")
var forwardPacketV6 = mustGUID("{7b964818-19c7-493a-b71f-832c3684d28c}")
var flagsCondition = mustGUID("{632ce23b-5167-435c-86d7-e903684aa80c}")

func encodeIPv6(s IPv6Spec) (*ipv6Allocation, error) {
	if e := s.Validate(); e != nil {
		return nil, e
	}
	if e := checkABI(); e != nil {
		return nil, e
	}
	if unsafe.Sizeof(provider{}) != 64 {
		return nil, errors.New("unexpected WFP provider ABI")
	}
	a := &ipv6Allocation{marker: []byte("NetLaunch/global-outbound-ipv6/v1")}
	a.name, _ = windows.UTF16FromString(s.Name())
	d := display{&a.name[0], &a.name[0]}
	a.provider = provider{Key: mustGUID(s.Provider), Display: d, Data: blob{uint32(len(a.marker)), &a.marker[0]}}
	a.sub = sublayer{Key: mustGUID(s.Sublayer), Display: d, Provider: &a.provider.Key, Weight: 0x7fff}
	// IS_LOOPBACK is documented for OUTBOUND_IPPACKET_V6, not IPFORWARD_V6.
	// Forwarded traffic is a distinct path; local ::1 delivery is not forwarded.
	a.conditions[0] = condition{Key: flagsCondition, Match: 8, Value: value{Type: 3, Data: 1}}
	for i, k := range []string{s.Outbound, s.Forward} {
		layer := outboundPacketV6
		if i == 1 {
			layer = forwardPacketV6
		}
		a.filters[i] = filter{Key: mustGUID(k), Display: d, Provider: &a.provider.Key, Layer: layer, Sublayer: a.sub.Key, Weight: value{Type: 1, Data: 15}, Action: action{Type: 0x1001}}
		if i == 0 {
			a.filters[i].Count = 1
			a.filters[i].Conditions = &a.conditions[0]
		}
	}
	return a, nil
}
func sameProviderPointer(a, b *windows.GUID) bool { return a != nil && b != nil && *a == *b }
func ipv6SublayerEqual(a, b sublayer) bool {
	// BFE may normalize the installed sublayer weight. Ownership is established
	// by its exact key, provider, display, flags and provider data, as for VPN WFP.
	return a.Key == b.Key && displayEqual(a.Display, b.Display) && a.Flags == 0 && sameProviderPointer(a.Provider, b.Provider) && a.ProviderData.Size == 0
}
func ipv6FilterEqual(a, b filter) bool {
	if !(a.Key == b.Key && displayEqual(a.Display, b.Display) && a.Flags == 0 && sameProviderPointer(a.Provider, b.Provider) && a.ProviderData.Size == 0 && a.Layer == b.Layer && a.Sublayer == b.Sublayer && a.Weight.Type == 1 && byte(a.Weight.Data) == 15 && a.Count == b.Count && a.Action == b.Action && a.Context == [2]uint64{} && a.Reserved == nil) {
		return false
	}
	if b.Count == 0 {
		return true
	}
	return b.Count == 1 && a.Conditions != nil && b.Conditions != nil && conditionEqual(*a.Conditions, *b.Conditions)
}
func (e *engine) inspectIPv6(s IPv6Spec) (IPv6Status, error) {
	a, err := encodeIPv6(s)
	if err != nil {
		return IPv6Status{}, err
	}
	defer runtime.KeepAlive(a)
	var status IPv6Status
	var p *provider
	key := a.provider.Key
	err = call("FwpmProviderGetByKey0", uintptr(e.handle), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&p)))
	if err != nil && !errors.Is(err, windows.Errno(0x80320005)) {
		return status, err
	}
	if err == nil {
		if p == nil {
			return status, errors.New("missing WFP IPv6 provider")
		}
		ok := p.Key == a.provider.Key && displayEqual(p.Display, a.provider.Display) && p.Flags == 0 && blobEqual(p.Data, a.provider.Data) && p.ServiceName == nil
		dll.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&p)))
		if !ok {
			return status, errors.New("global IPv6 provider changed externally")
		}
		status.Provider = true
	}
	var sub *sublayer
	key = a.sub.Key
	err = call("FwpmSubLayerGetByKey0", uintptr(e.handle), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&sub)))
	if err != nil && !errors.Is(err, windows.Errno(0x80320007)) {
		return status, err
	}
	if err == nil {
		if sub == nil {
			return status, errors.New("missing WFP IPv6 sublayer")
		}
		ok := ipv6SublayerEqual(*sub, a.sub)
		dll.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&sub)))
		if !ok {
			return status, errors.New("global IPv6 sublayer changed externally")
		}
		status.Sublayer = true
	}
	present := []*bool{&status.Outbound, &status.Forward}
	for i, w := range a.filters {
		var actual *filter
		key = w.Key
		err = call("FwpmFilterGetByKey0", uintptr(e.handle), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&actual)))
		if errors.Is(err, windows.Errno(0x80320003)) {
			continue
		}
		if err != nil {
			return status, err
		}
		if actual == nil {
			return status, errors.New("missing global IPv6 filter")
		}
		ok := ipv6FilterEqual(*actual, w)
		dll.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&actual)))
		if !ok {
			return status, errors.New("global IPv6 filter changed externally")
		}
		*present[i] = true
	}
	return status, nil
}
func InspectIPv6(s IPv6Spec) (IPv6Status, error) {
	e, err := open()
	if err != nil {
		return IPv6Status{}, err
	}
	defer e.close()
	return e.inspectIPv6(s)
}
func AddIPv6(s IPv6Spec) error {
	e, err := open()
	if err != nil {
		return err
	}
	defer e.close()
	a, err := encodeIPv6(s)
	if err != nil {
		return err
	}
	defer runtime.KeepAlive(a)
	return e.transaction(func() error {
		st, err := e.inspectIPv6(s)
		if err != nil {
			return err
		}
		if !st.Empty() {
			return errors.New("global IPv6 ownership key already exists")
		}
		if err = call("FwpmProviderAdd0", uintptr(e.handle), uintptr(unsafe.Pointer(&a.provider)), 0); err != nil {
			return err
		}
		if err = call("FwpmSubLayerAdd0", uintptr(e.handle), uintptr(unsafe.Pointer(&a.sub)), 0); err != nil {
			return err
		}
		for i := range a.filters {
			if err = call("FwpmFilterAdd0", uintptr(e.handle), uintptr(unsafe.Pointer(&a.filters[i])), 0, 0); err != nil {
				return err
			}
		}
		return nil
	})
}
func RemoveIPv6(s IPv6Spec) error {
	e, err := open()
	if err != nil {
		return err
	}
	defer e.close()
	return e.transaction(func() error {
		st, err := e.inspectIPv6(s)
		if err != nil {
			return err
		}
		for i, k := range []string{s.Outbound, s.Forward} {
			if []bool{st.Outbound, st.Forward}[i] {
				key := mustGUID(k)
				if err = call("FwpmFilterDeleteByKey0", uintptr(e.handle), uintptr(unsafe.Pointer(&key))); err != nil {
					return err
				}
			}
		}
		if st.Sublayer {
			key := mustGUID(s.Sublayer)
			if err = call("FwpmSubLayerDeleteByKey0", uintptr(e.handle), uintptr(unsafe.Pointer(&key))); err != nil {
				return err
			}
		}
		if st.Provider {
			key := mustGUID(s.Provider)
			return call("FwpmProviderDeleteByKey0", uintptr(e.handle), uintptr(unsafe.Pointer(&key)))
		}
		return nil
	})
}
