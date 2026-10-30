//go:build windows

package winwfp

import (
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"netlaunch/internal/winnet"
	"path/filepath"
	"runtime"
	"unsafe"
)

// ABI and condition identifiers are from Microsoft's WinSDK fwpmu/fwpmtypes.
// All calls are synchronous. Allocation holders keep union pointer values live.
type blob struct {
	Size uint32
	Data *byte
}
type display struct{ Name, Description *uint16 }
type value struct {
	Type uint32
	Data uint64
}

// Union pointers are read through the union storage, never converted back from
// uintptr. The allocation owner remains live for every synchronous native call.
func pointerValue(kind uint32, p unsafe.Pointer) value {
	// Store the union as numeric bits explicitly. Writing through a retyped
	// pointer slot did not survive the value copy on the supported toolchain.
	// p points into the heap allocation retained across the synchronous API.
	return value{Type: kind, Data: uint64(uintptr(p))}
}
func (v value) pointer() unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&v.Data)) }

type condition struct {
	Key   windows.GUID
	Match uint32
	Value value
}
type action struct {
	Type uint32
	Key  windows.GUID
}
type filter struct {
	Key             windows.GUID
	Display         display
	Flags           uint32
	Provider        *windows.GUID
	ProviderData    blob
	Layer, Sublayer windows.GUID
	Weight          value
	Count           uint32
	Conditions      *condition
	Action          action
	Context         [2]uint64
	Reserved        *windows.GUID
	ID              uint64
	EffectiveWeight value
}
type sublayer struct {
	Key          windows.GUID
	Display      display
	Flags        uint32
	Provider     *windows.GUID
	ProviderData blob
	Weight       uint16
}

var dll = windows.NewLazySystemDLL("fwpuclnt.dll")

func mustGUID(s string) windows.GUID {
	g, e := windows.GUIDFromString(s)
	if e != nil {
		panic(e)
	}
	return g
}

var (
	layer4       = mustGUID("{c38d57d1-05a7-4c33-904f-7fbceee60e82}")
	layer6       = mustGUID("{4a72393b-319f-44bc-84c3-ba54dcb3b6b4}")
	appKey       = mustGUID("{d78e1e87-8644-4ea5-9437-d809ecefc971}")
	interfaceKey = mustGUID("{4cd62a49-59c3-4969-b7f3-bda5d32890a4}")
	protocolKey  = mustGUID("{3971ef2b-623e-4f9a-8cb1-6e79b806b9a7}")
)

func call(name string, args ...uintptr) error {
	p := dll.NewProc(name)
	if e := p.Find(); e != nil {
		return e
	}
	code, _, _ := p.Call(args...)
	if code != 0 {
		return fmt.Errorf("%s: %w", name, windows.Errno(code))
	}
	return nil
}
func checkABI() error {
	if runtime.GOARCH != "amd64" || unsafe.Sizeof(filter{}) != 200 || unsafe.Sizeof(condition{}) != 40 || unsafe.Sizeof(sublayer{}) != 72 {
		return errors.New("WFP requires the verified Windows amd64 ABI")
	}
	return nil
}
func appID(exe string) ([]byte, error) {
	if !filepath.IsAbs(exe) {
		return nil, errors.New("absolute application path required")
	}
	p, e := windows.UTF16PtrFromString(exe)
	if e != nil {
		return nil, e
	}
	var b *blob
	if e = call("FwpmGetAppIdFromFileName0", uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&b))); e != nil {
		return nil, e
	}
	runtime.KeepAlive(p)
	if b == nil {
		return nil, errors.New("missing native application identity")
	}
	defer dll.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&b)))
	if b.Size < 4 || b.Size > 65536 || b.Size%2 != 0 || b.Data == nil {
		return nil, errors.New("invalid native application identity")
	}
	return append([]byte(nil), unsafe.Slice(b.Data, b.Size)...), nil
}
func Prepare(a winnet.Adapter, exe string) (Spec, error) {
	if e := checkABI(); e != nil {
		return Spec{}, e
	}
	b, e := appID(exe)
	if e != nil {
		return Spec{}, e
	}
	return New(a, exe, b)
}

type engine struct{ handle windows.Handle }

func open() (*engine, error) {
	if e := checkABI(); e != nil {
		return nil, e
	}
	e := &engine{}
	if err := call("FwpmEngineOpen0", 0, 10, 0, 0, uintptr(unsafe.Pointer(&e.handle))); err != nil {
		return nil, err
	}
	return e, nil
}
func (e *engine) close() { _ = call("FwpmEngineClose0", uintptr(e.handle)) }
func (e *engine) transaction(fn func() error) error {
	if err := call("FwpmTransactionBegin0", uintptr(e.handle), 0); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = call("FwpmTransactionAbort0", uintptr(e.handle))
		}
	}()
	if err := fn(); err != nil {
		return err
	}
	if err := call("FwpmTransactionCommit0", uintptr(e.handle)); err != nil {
		return err
	}
	committed = true
	return nil
}

type allocation struct {
	name       []uint16
	app        []byte
	luid       uint64
	appBlob    blob
	conditions [3][]condition
	filters    [3]filter
	sub        sublayer
}

func encode(s Spec) (*allocation, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if err := checkABI(); err != nil {
		return nil, err
	}
	a := &allocation{app: append([]byte(nil), s.AppID...), luid: s.Adapter.LUID}
	a.name, _ = windows.UTF16FromString(s.Name())
	d := display{&a.name[0], &a.name[0]}
	a.appBlob = blob{uint32(len(a.app)), &a.app[0]}
	a.sub = sublayer{Key: mustGUID(s.Sublayer), Display: d, Weight: 0x7fff}
	iface := condition{Key: interfaceKey, Match: 0, Value: pointerValue(4, unsafe.Pointer(&a.luid))}
	a.conditions[0] = []condition{iface, {Key: appKey, Match: 10, Value: pointerValue(12, unsafe.Pointer(&a.appBlob))}}
	a.conditions[1] = []condition{iface, {Key: protocolKey, Match: 10, Value: value{Type: 1, Data: 6}}}
	a.conditions[2] = []condition{iface}
	keys := []string{s.ForeignApp, s.NonTCP, s.IPv6}
	for i, key := range keys {
		layer := layer4
		if i == 2 {
			layer = layer6
		}
		a.filters[i] = filter{Key: mustGUID(key), Display: d, Layer: layer, Sublayer: a.sub.Key, Weight: value{Type: 1, Data: 15}, Count: uint32(len(a.conditions[i])), Conditions: &a.conditions[i][0], Action: action{Type: 0x1001}}
	}
	return a, nil
}
func blobEqual(a, b blob) bool {
	if a.Size != b.Size || a.Size > 65536 {
		return false
	}
	if a.Size == 0 {
		return true
	}
	if a.Data == nil || b.Data == nil {
		return false
	}
	return bytes.Equal(unsafe.Slice(a.Data, a.Size), unsafe.Slice(b.Data, b.Size))
}
func displayEqual(a, b display) bool {
	return windows.UTF16PtrToString(a.Name) == windows.UTF16PtrToString(b.Name) && windows.UTF16PtrToString(a.Description) == windows.UTF16PtrToString(b.Description)
}
func conditionEqual(a, b condition) bool {
	if a.Key != b.Key || a.Match != b.Match || a.Value.Type != b.Value.Type {
		return false
	}
	switch a.Value.Type {
	case 1:
		return byte(a.Value.Data) == byte(b.Value.Data)
	case 4:
		if a.Value.Data == 0 || b.Value.Data == 0 {
			return false
		}
		return *(*uint64)(a.Value.pointer()) == *(*uint64)(b.Value.pointer())
	case 12:
		if a.Value.Data == 0 || b.Value.Data == 0 {
			return false
		}
		return blobEqual(*(*blob)(a.Value.pointer()), *(*blob)(b.Value.pointer()))
	}
	return false
}
func filterEqual(actual, wanted filter) bool {
	if actual.Key != wanted.Key || !displayEqual(actual.Display, wanted.Display) || actual.Flags != 0 || actual.Provider != nil || actual.ProviderData.Size != 0 || actual.Layer != wanted.Layer || actual.Sublayer != wanted.Sublayer || actual.Weight.Type != 1 || byte(actual.Weight.Data) != 15 || actual.Count != wanted.Count || actual.Conditions == nil || actual.Action != wanted.Action || actual.Context != [2]uint64{} || actual.Reserved != nil {
		return false
	}
	a := unsafe.Slice(actual.Conditions, actual.Count)
	b := unsafe.Slice(wanted.Conditions, wanted.Count)
	used := make([]bool, len(b))
	for _, c := range a {
		matched := false
		for i, v := range b {
			if !used[i] && conditionEqual(c, v) {
				used[i] = true
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
func (e *engine) inspect(s Spec) (Status, error) {
	wanted, err := encode(s)
	if err != nil {
		return Status{}, err
	}
	defer runtime.KeepAlive(wanted)
	var result Status
	subKey := wanted.sub.Key
	var sub *sublayer
	err = call("FwpmSubLayerGetByKey0", uintptr(e.handle), uintptr(unsafe.Pointer(&subKey)), uintptr(unsafe.Pointer(&sub)))
	if err != nil && !errors.Is(err, windows.Errno(0x80320007)) {
		return result, err
	}
	if err == nil {
		if sub == nil {
			return result, errors.New("missing WFP sublayer response")
		}
		ok := sub.Key == wanted.sub.Key && displayEqual(sub.Display, wanted.sub.Display) && sub.Flags == 0 && sub.Provider == nil && sub.ProviderData.Size == 0 && sub.Weight == wanted.sub.Weight
		dll.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&sub)))
		if !ok {
			return result, errors.New("WFP sublayer changed externally")
		}
		result.Sublayer = true
	}
	exists := []*bool{&result.ForeignApp, &result.NonTCP, &result.IPv6}
	for i, w := range wanted.filters {
		var actual *filter
		key := w.Key
		err = call("FwpmFilterGetByKey0", uintptr(e.handle), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&actual)))
		if err != nil {
			if errors.Is(err, windows.Errno(0x80320003)) {
				continue
			}
			return result, err
		}
		if actual == nil {
			return result, errors.New("missing WFP filter response")
		}
		ok := filterEqual(*actual, w)
		dll.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&actual)))
		if !ok {
			return result, errors.New("WFP filter changed externally")
		}
		*exists[i] = true
	}
	return result, nil
}
func Inspect(s Spec) (Status, error) {
	if e := s.Validate(); e != nil {
		return Status{}, e
	}
	e, err := open()
	if err != nil {
		return Status{}, err
	}
	defer e.close()
	return e.inspect(s)
}

// Add installs the whole non-dynamic, non-persistent guard in one WFP
// transaction. Closing the caller's handle does not remove the protection.
func Add(s Spec) error {
	e, err := open()
	if err != nil {
		return err
	}
	defer e.close()
	a, err := encode(s)
	if err != nil {
		return err
	}
	defer runtime.KeepAlive(a)
	return e.transaction(func() error {
		status, err := e.inspect(s)
		if err != nil {
			return err
		}
		if !status.Empty() {
			return errors.New("WFP ownership key already exists")
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

// Remove checks every remaining item before deleting any. A changed guard is
// preserved; a partial but exact guard from interrupted cleanup is recoverable.
func Remove(s Spec) error {
	e, err := open()
	if err != nil {
		return err
	}
	defer e.close()
	return e.transaction(func() error {
		status, err := e.inspect(s)
		if err != nil {
			return err
		}
		keys := []string{s.ForeignApp, s.NonTCP, s.IPv6}
		exists := []bool{status.ForeignApp, status.NonTCP, status.IPv6}
		for i, k := range keys {
			if exists[i] {
				g := mustGUID(k)
				if err = call("FwpmFilterDeleteByKey0", uintptr(e.handle), uintptr(unsafe.Pointer(&g))); err != nil {
					return err
				}
			}
		}
		if status.Sublayer {
			g := mustGUID(s.Sublayer)
			if err = call("FwpmSubLayerDeleteByKey0", uintptr(e.handle), uintptr(unsafe.Pointer(&g))); err != nil {
				return err
			}
		}
		return nil
	})
}
