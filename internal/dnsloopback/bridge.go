// Package dnsloopback exposes an IPv4 DNS listener on the IPv6 loopback only.
package dnsloopback

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

type Bridge struct {
	tcp    net.Listener
	udp    net.PacketConn
	cancel context.CancelFunc
	Done   chan struct{}
}

// Start reserves both transports before returning. The upstream and listener
// must be literal loopback addresses; no DNS lookup or LAN listener is allowed.
func Start(parent context.Context, listen, upstream string) (*Bridge, error) {
	l, e := netip.ParseAddrPort(listen)
	if e != nil || l.Addr() != netip.IPv6Loopback() {
		return nil, errors.New("DNS bridge requires IPv6 loopback")
	}
	u, e := netip.ParseAddrPort(upstream)
	if e != nil || !u.Addr().Is4() || !u.Addr().IsLoopback() || u.Port() == 0 {
		return nil, errors.New("DNS bridge requires IPv4 loopback upstream")
	}
	tcp, e := net.Listen("tcp6", listen)
	if e != nil {
		return nil, e
	}
	udp, e := net.ListenPacket("udp6", tcp.Addr().String())
	if e != nil {
		tcp.Close()
		return nil, e
	}
	ctx, cancel := context.WithCancel(parent)
	b := &Bridge{tcp: tcp, udp: udp, cancel: cancel, Done: make(chan struct{})}
	stop := context.AfterFunc(ctx, func() { tcp.Close(); udp.Close() })
	var workers sync.WaitGroup
	slots := make(chan struct{}, 64)
	acquire := func() bool {
		select {
		case slots <- struct{}{}:
			return true
		default:
			return false
		}
	}
	var loops sync.WaitGroup
	loops.Add(2)
	go func() {
		defer loops.Done()
		defer cancel()
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			if !acquire() {
				c.Close()
				continue
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-slots }()
				defer c.Close()
				unhook := context.AfterFunc(ctx, func() { c.Close() })
				defer unhook()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				remote, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp4", upstream)
				if err != nil {
					return
				}
				defer remote.Close()
				unhookRemote := context.AfterFunc(ctx, func() { remote.Close() })
				defer unhookRemote()
				_ = remote.SetDeadline(time.Now().Add(5 * time.Second))
				// Forward bounded DNS frames, rather than a general byte tunnel.
				for i := 0; i < 16; i++ {
					if copyFrame(remote, c) != nil || copyFrame(c, remote) != nil {
						return
					}
				}
			}()
		}
	}()
	go func() {
		defer loops.Done()
		defer cancel()
		buffer := make([]byte, 65535)
		for {
			n, peer, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			if n < 12 || !acquire() {
				continue
			}
			query := append([]byte(nil), buffer[:n]...)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-slots }()
				remote, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "udp4", upstream)
				if err != nil {
					return
				}
				defer remote.Close()
				unhook := context.AfterFunc(ctx, func() { remote.Close() })
				defer unhook()
				_ = remote.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err = remote.Write(query); err != nil {
					return
				}
				response := make([]byte, 65535)
				n, err = remote.Read(response)
				if err == nil && n >= 12 && response[0] == query[0] && response[1] == query[1] {
					_, _ = udp.WriteTo(response[:n], peer)
				}
			}()
		}
	}()
	go func() { loops.Wait(); workers.Wait(); stop(); close(b.Done) }()
	return b, nil
}

func copyFrame(dst io.Writer, src io.Reader) error {
	var header [2]byte
	if _, e := io.ReadFull(src, header[:]); e != nil {
		return e
	}
	n := int(binary.BigEndian.Uint16(header[:]))
	if n < 12 {
		return errors.New("short DNS frame")
	}
	data := make([]byte, 2+n)
	copy(data, header[:])
	if _, e := io.ReadFull(src, data[2:]); e != nil {
		return e
	}
	_, e := io.Copy(dst, bytes.NewReader(data))
	return e
}

func (b *Bridge) Close() { b.cancel(); <-b.Done }
