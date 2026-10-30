//go:build windows

package socketbind

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

func loopback(t *testing.T) net.Interface {
	t.Helper()
	all, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, dev := range all {
		if dev.Flags&(net.FlagUp|net.FlagLoopback) == net.FlagUp|net.FlagLoopback {
			t.Logf("real loopback: %s index=%d", dev.Name, dev.Index)
			return dev
		}
	}
	t.Fatal("no up loopback interface")
	return net.Interface{}
}

func listener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestRoundTrip(t *testing.T) {
	dev := loopback(t)
	l := listener(t)
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 4)
		if _, err = io.ReadFull(c, b); err == nil {
			_, err = c.Write(b)
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := DialContext(ctx, dev.Name, "tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	raw, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var selected int
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		selected, optionErr = syscall.GetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, ipUnicastIF)
	}); err != nil {
		t.Fatal(err)
	}
	// Windows returns this option in host byte order, unlike its set value.
	if optionErr != nil || selected != dev.Index {
		t.Fatalf("selected interface=%d want=%d err=%v", selected, dev.Index, optionErr)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	if string(b) != "ping" {
		t.Fatalf("echo %q", b)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRejectInput(t *testing.T) {
	dev := loopback(t)
	cases := []struct{ iface, network, address string }{
		{dev.Name, "tcp", "127.0.0.1:1"}, {dev.Name, "udp4", "127.0.0.1:1"},
		{dev.Name, "tcp6", "[::1]:1"}, {dev.Name, "tcp4", "[::1]:1"},
		{dev.Name, "tcp4", "[::ffff:127.0.0.1]:1"}, {dev.Name, "tcp4", "localhost:1"},
		{dev.Name, "tcp4", "example.invalid:443"}, {dev.Name, "tcp4", "127.0.0.1:http"},
		{dev.Name, "tcp4", "127.0.0.1:0"}, {dev.Name, "tcp4", "127.0.0.1:65536"},
		{dev.Name, "tcp4", "127.0.0.1"}, {dev.Name, "tcp4", "127.0.0.1:-1"},
		{"", "tcp4", "127.0.0.1:1"}, {"netlaunch-missing-interface", "tcp4", "127.0.0.1:1"},
	}
	for _, tc := range cases {
		t.Run(tc.iface+"/"+tc.network+"/"+tc.address, func(t *testing.T) {
			c, err := DialContext(context.Background(), tc.iface, tc.network, tc.address)
			if c != nil {
				c.Close()
				t.Fatal("unexpected connection")
			}
			if err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	if _, err := DialContext(nil, dev.Name, "tcp4", "127.0.0.1:1"); err == nil {
		t.Fatal("nil context accepted")
	}
}

func TestCanceled(t *testing.T) {
	dev := loopback(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, err := DialContext(ctx, dev.Name, "tcp4", "127.0.0.1:1")
	if c != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v %v", c, err)
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err = DialContext(ctx, dev.Name, "tcp4", "127.0.0.1:1")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestOptionBytesAndFailure(t *testing.T) {
	marker := errors.New("injected setsockopt failure")
	for _, index := range []uint32{1, 0x010203, 0xabcdef} {
		err := setInterface(42, index, func(fd syscall.Handle, level, opt, value int) error {
			if fd != 42 || level != syscall.IPPROTO_IP || opt != 31 {
				t.Fatal("wrong socket option")
			}
			var got, want [4]byte
			binary.NativeEndian.PutUint32(got[:], uint32(value))
			binary.BigEndian.PutUint32(want[:], index)
			if !bytes.Equal(got[:], want[:]) {
				t.Fatalf("bytes %x want %x", got, want)
			}
			return marker
		})
		if !errors.Is(err, marker) {
			t.Fatalf("lost option failure: %v", err)
		}
	}
}

func TestDialOptionFailureNoFallback(t *testing.T) {
	l := listener(t)
	marker := errors.New("injected bind rejection")
	calls := 0
	d := net.Dialer{ControlContext: interfaceControl(uint32(loopback(t).Index), func(syscall.Handle, int, int, int) error { calls++; return marker })}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp4", l.Addr().String())
	if c != nil {
		c.Close()
		t.Fatal("unexpected fallback connection")
	}
	if !errors.Is(err, marker) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	l.(*net.TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond))
	accepted, err := l.Accept()
	if accepted != nil {
		accepted.Close()
		t.Fatal("server received fallback")
	}
	if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatalf("accept: %v", err)
	}
}

func TestCancelDuringControl(t *testing.T) {
	l := listener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := net.Dialer{ControlContext: interfaceControl(uint32(loopback(t).Index), func(syscall.Handle, int, int, int) error { cancel(); return nil })}
	c, err := d.DialContext(ctx, "tcp4", l.Addr().String())
	if c != nil {
		c.Close()
		t.Fatal("unexpected connection")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}
