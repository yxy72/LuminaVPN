package lease

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"netlaunch/internal/dnswire"
)

// Read a real TCP DNS reply on loopback. The documentation resolver address
// is deliberately mapped to this listener; no system DNS or VPN is used.
// A short CNAME TTL must bound authorization despite the long terminal A TTL.
func cnameDNSGrant(t *testing.T, host, ip string) dnswire.Answer {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		var size [2]byte
		if _, e = io.ReadFull(c, size[:]); e != nil {
			done <- e
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(size[:]))
		if len(q) < 12 || len(q) > 512 {
			done <- fmt.Errorf("invalid fixture query size")
			return
		}
		if _, e = io.ReadFull(c, q); e != nil {
			done <- e
			return
		}
		binary.BigEndian.PutUint16(q[2:4], 0x8180)
		binary.BigEndian.PutUint16(q[6:8], 2)
		var alias []byte
		for _, label := range strings.Split("lease-target.test", ".") {
			alias = append(alias, byte(len(label)))
			alias = append(alias, label...)
		}
		alias = append(alias, 0)
		q = append(q, 0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 2, 0, byte(len(alias)))
		q = append(q, alias...)
		q = append(q, alias...)
		q = append(q, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4)
		q = append(q, net.ParseIP(ip).To4()...)
		binary.BigEndian.PutUint16(size[:], uint16(len(q)))
		_, e = io.Copy(c, bytes.NewReader(append(size[:], q...)))
		done <- e
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	answers, queryErr := dnswire.Query(ctx, func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp4" || address != "192.0.2.53:53" {
			return nil, fmt.Errorf("unexpected fixture resolver")
		}
		return (&net.Dialer{}).DialContext(ctx, network, l.Addr().String())
	}, "192.0.2.53", host)
	l.Close() // Unblock Accept if Query failed before connecting.
	serverErr := <-done
	if queryErr != nil || serverErr != nil {
		t.Fatalf("CNAME DNS fixture: query=%v server=%v", queryErr, serverErr)
	}
	if len(answers) != 1 || answers[0].IP != ip || answers[0].Domain != host || answers[0].TTL != 2 || answers[0].ExpiresAt.Sub(answers[0].ResolvedAt) != 2*time.Second {
		t.Fatalf("CNAME did not bound terminal A authorization: %+v", answers)
	}
	return answers[0]
}

// The first resolver deliberately ignores cancellation and receives a real
// delayed TCP reply. Neither a new VPN generation, a newer refresh, nor the
// query deadline may allow that reply to restore obsolete authorization.
func TestLateTCPDNSReplyCannotRestoreAuthorization(t *testing.T) {
	for _, mode := range []string{"generation", "newer_refresh", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			a, e := New([]string{host}, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer a.Revoke()
			old := a.Begin(context.Background())
			l, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			received := make(chan struct{})
			release := make(chan struct{})
			serverDone := make(chan error, 1)
			go func() {
				c, e := l.Accept()
				if e != nil {
					serverDone <- e
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var size [2]byte
				if _, e = io.ReadFull(c, size[:]); e != nil {
					serverDone <- e
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(size[:]))
				if len(q) < 12 || len(q) > 512 {
					serverDone <- fmt.Errorf("invalid query")
					return
				}
				if _, e = io.ReadFull(c, q); e != nil {
					serverDone <- e
					return
				}
				close(received)
				select {
				case <-release:
				case <-time.After(5 * time.Second):
					serverDone <- fmt.Errorf("release timeout")
					return
				}
				binary.BigEndian.PutUint16(q[2:4], 0x8180)
				binary.BigEndian.PutUint16(q[6:8], 1)
				q = append(q, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 8)
				binary.BigEndian.PutUint16(size[:], uint16(len(q)))
				_, e = io.Copy(c, bytes.NewReader(append(size[:], q...)))
				serverDone <- e
			}()
			done := make(chan error, 1)
			queryCtx := make(chan context.Context, 1)
			wireParsed := make(chan bool, 1)
			parent := context.Background()
			if mode == "deadline" {
				var cancel context.CancelFunc
				parent, cancel = context.WithTimeout(parent, 500*time.Millisecond)
				defer cancel()
			}
			go func() {
				done <- old.Refresh(parent, host, func(ctx context.Context, domain string) ([]dnswire.Answer, error) {
					queryCtx <- ctx
					independent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					answers, e := dnswire.Query(independent, func(ctx context.Context, network, address string) (net.Conn, error) {
						if network != "tcp4" || address != "192.0.2.53:53" {
							return nil, fmt.Errorf("unexpected resolver")
						}
						return (&net.Dialer{}).DialContext(ctx, network, l.Addr().String())
					}, "192.0.2.53", domain)
					wireParsed <- e == nil && len(answers) == 1 && answers[0].IP == "192.0.2.8"
					return answers, e
				})
			}()
			ctx := <-queryCtx
			select {
			case <-received:
			case <-time.After(2 * time.Second):
				t.Fatal("no wire query")
			}
			current := old
			if mode == "generation" {
				current = a.Begin(context.Background())
			}
			if mode == "deadline" {
				<-ctx.Done()
			} else {
				fresh := cnameDNSGrant(t, host, "192.0.2.9")
				if e := current.Refresh(context.Background(), host, func(context.Context, string) ([]dnswire.Answer, error) { return []dnswire.Answer{fresh}, nil }); e != nil {
					t.Fatal(e)
				}
			}
			close(release)
			if e := <-done; e == nil {
				t.Fatal("late reply accepted")
			}
			if !<-wireParsed {
				t.Fatal("late DNS reply did not traverse TCP parser")
			}
			if e := <-serverDone; e != nil {
				t.Fatal(e)
			}
			answers, e := current.Lookup(host)
			if mode == "deadline" {
				if e == nil {
					t.Fatal("expired query granted")
				}
			} else if e != nil || len(answers) != 1 || answers[0].IP != "192.0.2.9" {
				t.Fatal("fresh grant replaced", e)
			}
			if mode == "generation" {
				if _, e := old.Lookup(host); e == nil {
					t.Fatal("old generation reopened")
				}
			}
		})
	}
}
