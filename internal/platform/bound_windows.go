//go:build windows

package platform

import (
	"context"
	"net"
	"netlaunch/internal/socketbind"
)

// Socket binding is available before the Windows lifecycle is enabled. It does
// not authorize traffic or install routes; callers must supply those guards.
func BoundDial(iface string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return socketbind.DialContext(ctx, iface, network, address)
	}
}
