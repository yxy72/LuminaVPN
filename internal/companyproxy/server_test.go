package companyproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

var credentials = Credentials{"company", strings.Repeat("test-secret-", 4)}

func client(t *testing.T, dial Dial) net.Conn {
	t.Helper()
	s, e := New(credentials, dial)
	if e != nil {
		t.Fatal(e)
	}
	left, right := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.handle(ctx, right); close(done) }()
	left.SetDeadline(time.Now().Add(2 * time.Second))
	t.Cleanup(func() {
		cancel()
		left.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("ingress did not stop")
		}
	})
	return left
}
func read(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, e := io.ReadFull(c, b); e != nil {
		t.Fatal(e)
	}
	return b
}
func auth(t *testing.T, c net.Conn, password string) {
	t.Helper()
	c.Write([]byte{5, 1, 2})
	if b := read(t, c, 2); b[1] != 2 {
		t.Fatal(b)
	}
	p := append([]byte{1, byte(len(credentials.Username))}, []byte(credentials.Username)...)
	p = append(p, byte(len(password)))
	p = append(p, []byte(password)...)
	c.Write(p)
}
func request(target string, port int) []byte {
	b := append([]byte{5, 1, 0, 3, byte(len(target))}, []byte(target)...)
	return append(b, byte(port>>8), byte(port))
}

func TestAuthenticationRequired(t *testing.T) {
	for _, mode := range []string{"no_auth", "bad_password"} {
		t.Run(mode, func(t *testing.T) {
			c := client(t, func(context.Context, string, int) (net.Conn, error) {
				t.Error("unauthenticated request dialed")
				return nil, errors.New("denied")
			})
			if mode == "no_auth" {
				c.Write([]byte{5, 1, 0})
				if b := read(t, c, 2); b[1] != 255 {
					t.Fatal(b)
				}
			} else {
				auth(t, c, "wrong-password")
				if b := read(t, c, 2); b[1] != 1 {
					t.Fatal(b)
				}
			}
		})
	}
}

func TestAuthenticatedDomainRelay(t *testing.T) {
	called := make(chan string, 1)
	c := client(t, func(ctx context.Context, host string, port int) (net.Conn, error) {
		called <- net.JoinHostPort(host, "8443")
		if port != 8443 {
			t.Error(port)
		}
		l, r := net.Pipe()
		go func() { defer r.Close(); b := make([]byte, 4); io.ReadFull(r, b); r.Write(b) }()
		return l, nil
	})
	auth(t, c, credentials.Password)
	if b := read(t, c, 2); b[1] != 0 {
		t.Fatal(b)
	}
	c.Write(request("Service.Example.com.", 8443))
	if b := read(t, c, 10); b[1] != 0 {
		t.Fatal(b)
	}
	c.Write([]byte("ping"))
	if string(read(t, c, 4)) != "ping" {
		t.Fatal("relay changed bytes")
	}
	if got := <-called; got != "service.example.com:8443" {
		t.Fatal(got)
	}
}

func TestMalformedOrUnsupportedRequestsNeverDial(t *testing.T) {
	for name, q := range map[string][]byte{
		"udp": {5, 3, 0, 1}, "bind": {5, 2, 0, 1}, "ipv6": {5, 1, 0, 4},
		"suffix": request("*.example.com", 443), "zero_port": request("service.example.com", 0),
		"loopback": {5, 1, 0, 1, 127, 0, 0, 1}, "reserved": {5, 1, 1, 3},
	} {
		t.Run(name, func(t *testing.T) {
			c := client(t, func(context.Context, string, int) (net.Conn, error) {
				t.Error("unsupported request dialed")
				return nil, nil
			})
			auth(t, c, credentials.Password)
			read(t, c, 2)
			go func() { _, _ = c.Write(q) }()
			if b := read(t, c, 10); b[1] == 0 {
				t.Fatal("request accepted")
			}
		})
	}
}

func TestLiteralRequestStillRequiresAuthorization(t *testing.T) {
	called := false
	c := client(t, func(_ context.Context, target string, port int) (net.Conn, error) {
		called = true
		if target != "10.1.2.3" || port != 53 {
			t.Error(target, port)
		}
		return nil, errors.New("not authorized")
	})
	auth(t, c, credentials.Password)
	read(t, c, 2)
	q := []byte{5, 1, 0, 1, 10, 1, 2, 3, 0, 0}
	binary.BigEndian.PutUint16(q[8:], 53)
	c.Write(q)
	if b := read(t, c, 10); b[1] != 2 {
		t.Fatal(b)
	}
	if !called {
		t.Fatal("policy callback missing")
	}
}

func TestProxyRejectsLANAndWeakCredentials(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:1234", "192.168.1.2:1234", "[::1]:1234", "127.0.0.1:0"} {
		if _, e := Proxy(addr, credentials); e == nil {
			t.Fatal(addr)
		}
	}
	if _, e := Proxy("127.0.0.1:1234", Credentials{"company", "short"}); e == nil {
		t.Fatal("weak credentials")
	}
}
