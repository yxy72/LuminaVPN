//go:build windows

package app

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"sync"
	"syscall"

	"netlaunch/internal/winnet"
	"netlaunch/internal/winservice"
)

const authSocketWorkerAbortCode = 74
const authIPUnicastIF = 31

type serviceAuthSocketDependencies struct {
	discover func() (winnet.Physical, error)
	set      func(uintptr, uint32) error
	get      func(uintptr) (uint32, error)
	abort    func(int)
}
type serviceAuthSocketGuard struct {
	mu       sync.Mutex
	ctx      context.Context
	plan     winservice.UserAuthNetworkBinding
	cancel   context.CancelFunc
	deps     serviceAuthSocketDependencies
	failure  error
	verified uint64
}

func newServiceAuthSocketGuard(ctx context.Context, plan winservice.UserAuthNetworkBinding, cancel context.CancelFunc) (*serviceAuthSocketGuard, error) {
	return newServiceAuthSocketGuardWith(ctx, plan, cancel, serviceAuthSocketDependencies{
		discover: winnet.Discover,
		set: func(fd uintptr, index uint32) error {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], index)
			return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, authIPUnicastIF, int(int32(binary.NativeEndian.Uint32(b[:]))))
		},
		get: func(fd uintptr) (uint32, error) {
			v, err := syscall.GetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, authIPUnicastIF)
			return uint32(v), err
		},
		abort: os.Exit,
	})
}
func newServiceAuthSocketGuardWith(ctx context.Context, plan winservice.UserAuthNetworkBinding, cancel context.CancelFunc, deps serviceAuthSocketDependencies) (*serviceAuthSocketGuard, error) {
	if ctx == nil || ctx.Err() != nil || cancel == nil || plan.Validate() != nil || plan.Index > 0x00ffffff || deps.discover == nil || deps.set == nil || deps.get == nil || deps.abort == nil {
		return nil, errors.New("verified private physical authentication plan required")
	}
	return &serviceAuthSocketGuard{ctx: ctx, plan: plan, cancel: cancel, deps: deps}, nil
}
func (g *serviceAuthSocketGuard) matches(actual winnet.Physical) bool {
	return actual.Adapter.Up && actual.Adapter.Hardware && actual.Adapter.Index == g.plan.Index && actual.Adapter.LUID == g.plan.LUID && strings.EqualFold(actual.Adapter.GUID, g.plan.GUID) && actual.Address == g.plan.Address && actual.Gateway == g.plan.Gateway
}
func (g *serviceAuthSocketGuard) reject() {
	if g.failure == nil {
		g.failure = errors.New("physical authentication socket verification failed")
	}
	g.cancel()
	// OpenConnect's pre-connect callback is void: cancel/shutdown alone cannot
	// prevent its next synchronous connect. This isolated worker must not return
	// to C on a failed binding. Exiting also avoids closing a reused descriptor.
	g.deps.abort(authSocketWorkerAbortCode)
	panic("isolated authentication abort unexpectedly returned")
}

// Protect accepts the lower 32-bit C int fd from the API-5 callback. Success
// returns only after both independent live identity checks and option readback.
func (g *serviceAuthSocketGuard) Protect(raw uintptr) {
	g.mu.Lock()
	defer g.mu.Unlock()
	fd := int32(uint32(raw))
	if g.failure != nil || g.ctx.Err() != nil || fd < 0 {
		g.reject()
	}
	actual, err := g.deps.discover()
	if err != nil || !g.matches(actual) {
		g.reject()
	}
	if err = g.deps.set(uintptr(uint32(fd)), g.plan.Index); err != nil {
		g.reject()
	}
	index, err := g.deps.get(uintptr(uint32(fd)))
	if err != nil || index != g.plan.Index {
		g.reject()
	}
	actual, err = g.deps.discover()
	if err != nil || !g.matches(actual) {
		g.reject()
	}
	g.verified++
}
func (g *serviceAuthSocketGuard) Err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failure != nil {
		return g.failure
	}
	if g.ctx.Err() != nil {
		return errors.New("physical authentication cancelled")
	}
	if g.verified == 0 {
		return errors.New("no verified physical authentication socket")
	}
	return nil
}
