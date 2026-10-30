//go:build windows

package socketbind

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// IP_UNICAST_IF expects a DWORD containing the IPv4 interface index in network
// byte order. SetsockoptInt writes a native-endian int32, so convert explicitly.
const ipUnicastIF = 31

type socketOption func(syscall.Handle, int, int, int) error

func setInterface(fd uintptr, index uint32, set socketOption) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], index)
	value := int(int32(binary.NativeEndian.Uint32(b[:])))
	if err := set(syscall.Handle(fd), syscall.IPPROTO_IP, ipUnicastIF, value); err != nil {
		return fmt.Errorf("socketbind: IP_UNICAST_IF index %d: %w", index, err)
	}
	return nil
}

func interfaceControl(index uint32, set socketOption) func(context.Context, string, string, syscall.RawConn) error {
	return func(ctx context.Context, network, address string, raw syscall.RawConn) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var optionErr error
		if err := raw.Control(func(fd uintptr) { optionErr = setInterface(fd, index, set) }); err != nil {
			return fmt.Errorf("socketbind: socket control: %w", err)
		}
		return optionErr
	}
}

func dialInterface(ctx context.Context, index uint32, address string) (net.Conn, error) {
	d := net.Dialer{ControlContext: interfaceControl(index, syscall.SetsockoptInt)}
	return d.DialContext(ctx, "tcp4", address)
}

// DialChecked keeps the selected source and native adapter generation fixed at
// socket creation and verifies it again after connect. validate must be local,
// bounded and must not acquire a lock held by the caller.
func DialChecked(ctx context.Context, index uint32, source, address string, validate func() error) (net.Conn, error) {
	ap, e := netip.ParseAddrPort(address)
	ip, e2 := netip.ParseAddr(source)
	if e != nil || e2 != nil || !ap.Addr().Is4() || ap.Port() == 0 || !ip.Is4() || index == 0 || validate == nil {
		return nil, fmt.Errorf("invalid checked IPv4 binding")
	}
	control := interfaceControl(index, syscall.SetsockoptInt)
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(ip.AsSlice())}, ControlContext: func(ctx context.Context, network, addr string, raw syscall.RawConn) error {
		if e := validate(); e != nil {
			return e
		}
		return control(ctx, network, addr, raw)
	}}
	if e = validate(); e != nil {
		return nil, e
	}
	c, e := d.DialContext(ctx, "tcp4", ap.String())
	if e != nil {
		return nil, e
	}
	if e = validate(); e != nil {
		c.Close()
		return nil, e
	}
	return c, nil
}
