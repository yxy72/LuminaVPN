// Package socketbind opens TCP/IPv4 connections bound to a named Windows
// interface. It never resolves DNS names or falls back to an unbound socket.
package socketbind

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// DialContext accepts only network "tcp4" and a literal IPv4 address with a
// numeric port in 1..65535. The interface is looked up afresh on every call and
// must be up. Context cancellation governs dialing, not subsequent I/O.
// Interface selection does not create routes or prevent later OS routing changes.
func DialContext(ctx context.Context, iface, network, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, fmt.Errorf("socketbind: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network != "tcp4" {
		return nil, fmt.Errorf("socketbind: only tcp4 is supported")
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !ap.Addr().Is4() || ap.Port() == 0 {
		return nil, fmt.Errorf("socketbind: expected literal IPv4:numeric-port (1..65535)")
	}
	if iface == "" {
		return nil, fmt.Errorf("socketbind: empty interface name")
	}
	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("socketbind: interface %q: %w", iface, err)
	}
	if dev.Flags&net.FlagUp == 0 || dev.Index <= 0 || uint64(dev.Index) > 0xffffff {
		return nil, fmt.Errorf("socketbind: interface %q must be up with a valid index", iface)
	}
	return dialInterface(ctx, uint32(dev.Index), ap.String())
}
