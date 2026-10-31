package dnsloopback

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestBridgeBothTransportsAndCancellation(t *testing.T) {
	tcp, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer tcp.Close()
	udp, e := net.ListenPacket("udp4", tcp.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	query := make([]byte, 12)
	query[0] = 42
	query[1] = 13
	response := append([]byte(nil), query...)
	response[2] = 128
	go func() {
		b := make([]byte, 512)
		n, peer, e := udp.ReadFrom(b)
		if e == nil && bytes.Equal(b[:n], query) {
			_, _ = udp.WriteTo(response, peer)
		}
	}()
	go func() {
		c, e := tcp.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 14)
		if _, e = io.ReadFull(c, b); e == nil && bytes.Equal(b[2:], query) {
			copy(b[2:], response)
			_, _ = c.Write(b)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b, e := Start(ctx, "[::1]:0", tcp.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	addr := b.tcp.Addr().String()
	for _, network := range []string{"udp6", "tcp6"} {
		c, e := net.DialTimeout(network, addr, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		payload := query
		if network == "tcp6" {
			payload = make([]byte, 14)
			binary.BigEndian.PutUint16(payload[:2], 12)
			copy(payload[2:], query)
		}
		if _, e = c.Write(payload); e != nil {
			t.Fatal(e)
		}
		got := make([]byte, len(payload))
		if _, e = io.ReadFull(c, got); e != nil {
			t.Fatal(e)
		}
		c.Close()
		if network == "tcp6" {
			got = got[2:]
		}
		if !bytes.Equal(got, response) {
			t.Fatal("DNS response changed")
		}
	}
	// An idle client must not keep the bridge alive after coordinator exit.
	idle, e := net.Dial("tcp6", addr)
	if e != nil {
		t.Fatal(e)
	}
	defer idle.Close()
	cancel()
	select {
	case <-b.Done:
	case <-time.After(time.Second):
		t.Fatal("bridge did not stop")
	}
	rebound, e := net.Listen("tcp6", addr)
	if e != nil {
		t.Fatal("listener leaked", e)
	}
	rebound.Close()
}

func TestBridgeRejectsNonLoopbackAndPartialBind(t *testing.T) {
	for _, pair := range [][2]string{{"[::]:53", "127.0.0.1:53"}, {"[::1]:0", "192.0.2.1:53"}, {"[::1]:0", "localhost:53"}} {
		if b, e := Start(context.Background(), pair[0], pair[1]); e == nil {
			b.Close()
			t.Fatal("nonloopback accepted")
		}
	}
	busy, e := net.ListenPacket("udp6", "[::1]:0")
	if e != nil {
		t.Fatal(e)
	}
	defer busy.Close()
	if b, e := Start(context.Background(), busy.LocalAddr().String(), "127.0.0.1:53"); e == nil {
		b.Close()
		t.Fatal("UDP conflict accepted")
	}
	tcp, e := net.Listen("tcp6", busy.LocalAddr().String())
	if e != nil {
		t.Fatal("partial TCP bind leaked", e)
	}
	tcp.Close()
}
