//go:build windows

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"netlaunch/internal/securefile"
	"netlaunch/internal/socketbind"
	"netlaunch/internal/winnet"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

func tcpProbe(a winnet.Adapter, port int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, e := socketbind.DialChecked(ctx, a.Index, "192.0.2.1", fmt.Sprintf("192.0.2.2:%d", port), func() error { return winnet.ValidateAdapter(a, "192.0.2.1") })
	if e == nil {
		c.Close()
	}
	return e
}
func foreignProbe(files securefile.AdminStore, id string) error {
	var a winnet.Adapter
	if e := read(files, id, "probe-adapter.json", &a); e != nil {
		return e
	}
	e := tcpProbe(a, 18445)
	result := map[string]bool{"connected": e == nil, "access_denied": errors.Is(e, syscall.Errno(10013))}
	return files.Write(filepath.Join(id, "probe-foreign.json"), result)
}
func runForeign(files securefile.AdminStore, id string) (map[string]bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e := exec.CommandContext(ctx, filepath.Join(files.Root, id, "probe-foreign.exe"), "dial-foreign", "--run", id).Run()
	if e != nil {
		return nil, e
	}
	var result map[string]bool
	e = read(files, id, "probe-foreign.json", &result)
	return result, e
}
func udpProbe(a winnet.Adapter) error {
	d := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1")}, Control: func(_, _ string, c syscall.RawConn) error {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], a.Index)
		var err error
		e := c.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, 31, int(binary.NativeEndian.Uint32(buf[:])))
		})
		if e != nil {
			return e
		}
		return err
	}}
	c, e := d.Dial("udp4", "192.0.2.2:18444")
	if e != nil {
		return e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	_, e = c.Write([]byte("probe"))
	if e != nil {
		return e
	}
	buf := make([]byte, 32)
	n, e := c.Read(buf)
	if e != nil {
		return e
	}
	if string(buf[:n]) != "probe" {
		return errors.New("invalid fixture UDP echo")
	}
	return nil
}

func waitAddress(a winnet.Adapter) error {
	until := time.Now().Add(5 * time.Second)
	for {
		if e := winnet.ValidateAdapter(a, "192.0.2.1"); e == nil {
			return nil
		}
		if time.Now().After(until) {
			return errors.New("probe address not ready")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
