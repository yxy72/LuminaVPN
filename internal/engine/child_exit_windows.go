//go:build windows

package engine

import (
	"errors"

	"netlaunch/internal/platform"
)

var errVPNAuthenticationRequired = errors.New("VPN session rejected; run auth")

type windowsChildExit struct {
	identity platform.Identity
	done     chan struct{}
	code     uint32
	err      error
}

// Only the coordinator goroutine accesses the map. The waiter publishes its
// result by closing done, and retains its own entry if a newer launch replaces it.
func (g *windowsChildren) trackExit(role string, id platform.Identity, wait func() (uint32, error)) {
	if g.exits == nil {
		g.exits = make(map[string]*windowsChildExit)
	}
	result := &windowsChildExit{identity: id, done: make(chan struct{})}
	g.exits[role] = result
	go func() { result.code, result.err = wait(); close(result.done) }()
}

func (g *windowsChildren) childExit(role string) (*windowsChildExit, bool) {
	result := g.exits[role]
	if result == nil {
		return nil, false
	}
	select {
	case <-result.done:
		return result, true
	default:
		return nil, false
	}
}

func (g *windowsChildren) vpnAuthenticationRejected() bool {
	result, complete := g.childExit("vpn")
	// The bundled OpenConnect maps a server-rejected CSTP cookie to exit 2.
	// A pinned-client TLS loopback fixture distinguishes 401 from transient 503.
	return complete && result.err == nil && result.code == 2
}
