//go:build windows

package winnet

import (
	"errors"
	"golang.org/x/sys/windows"
	"sync"
	"sync/atomic"
	"unsafe"
)

// PowerWatch invalidates a VPN generation on both suspend and resume. Epoch
// is process-local; callers persist the value only within their own run.
type PowerWatch struct {
	epoch  atomic.Uint64
	id     uintptr
	handle windows.Handle
	mu     sync.Mutex
}

var powerWatches sync.Map
var powerIDs atomic.Uint64
var powerDLL = windows.NewLazySystemDLL("powrprof.dll")
var powerCallback = windows.NewCallback(func(context uintptr, event uint32, _ uintptr) uintptr {
	v, ok := powerWatches.Load(context)
	if !ok {
		return 0
	}
	return advancePower(v.(*PowerWatch), event)

})

func WatchPower() (*PowerWatch, error) {
	p := &PowerWatch{id: uintptr(powerIDs.Add(1))}
	p.epoch.Store(2)
	powerWatches.Store(p.id, p)
	recipient := struct{ Callback, Context uintptr }{powerCallback, p.id}
	register := powerDLL.NewProc("PowerRegisterSuspendResumeNotification")
	if e := register.Find(); e != nil {
		powerWatches.Delete(p.id)
		return nil, e
	}
	code, _, _ := register.Call(2, uintptr(unsafe.Pointer(&recipient)), uintptr(unsafe.Pointer(&p.handle)))
	if code != 0 || p.handle == 0 {
		powerWatches.Delete(p.id)
		if code == 0 {
			return nil, errors.New("missing power notification handle")
		}
		return nil, windows.Errno(code)
	}
	return p, nil
}
func (p *PowerWatch) Epoch() (uint64, bool) { v := p.epoch.Load(); return v &^ 1, v&1 == 0 }
func (p *PowerWatch) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.handle == 0 {
		return nil
	}
	code, _, _ := powerDLL.NewProc("PowerUnregisterSuspendResumeNotification").Call(uintptr(p.handle))
	if code != 0 {
		return windows.Errno(code)
	}
	p.handle = 0
	powerWatches.Delete(p.id)
	return nil
}

func advancePower(p *PowerWatch, event uint32) uintptr {
	for {
		old := p.epoch.Load()
		next := (old &^ 1) + 2
		switch event {
		case 4:
			next |= 1
		case 7, 18:
		default:
			return 0
		}
		if p.epoch.CompareAndSwap(old, next) {
			return 0
		}
	}
}
