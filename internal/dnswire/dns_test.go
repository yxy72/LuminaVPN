package dnswire

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func dnsName(s string) []byte {
	out := []byte{}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			out = append(out, byte(i-start))
			out = append(out, s[start:i]...)
			start = i + 1
		}
	}
	return append(out, 0)
}
func response() []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b, 42)
	binary.BigEndian.PutUint16(b[2:], 0x8180)
	binary.BigEndian.PutUint16(b[4:], 1)
	b = append(b, dnsName("service.example.com")...)
	return append(b, 0, 1, 0, 1)
}
func rr(b []byte, owner string, typ uint16, ttl uint32, data []byte) []byte {
	binary.BigEndian.PutUint16(b[6:], binary.BigEndian.Uint16(b[6:])+1)
	b = append(b, dnsName(owner)...)
	h := make([]byte, 10)
	binary.BigEndian.PutUint16(h, typ)
	binary.BigEndian.PutUint16(h[2:], 1)
	binary.BigEndian.PutUint32(h[4:], ttl)
	binary.BigEndian.PutUint16(h[8:], uint16(len(data)))
	return append(append(b, h...), data...)
}
func TestCNAMELeaseTTLAndUnrelatedAnswers(t *testing.T) {
	b := response()
	b = rr(b, "service.example.com", 5, 20, dnsName("alias.example.com"))
	b = rr(b, "alias.example.com", 1, 90, []byte{10, 1, 2, 3})
	b = rr(b, "unrelated.example.com", 1, 30, []byte{10, 1, 2, 4})
	now := time.Now()
	a, e := Parse(b, 42, "service.example.com", "10.1.0.53", now)
	if e != nil {
		t.Fatal(e)
	}
	if len(a) != 1 || a[0].IP != "10.1.2.3" || a[0].TTL != 20 || !a[0].ExpiresAt.Equal(now.Add(20*time.Second)) {
		t.Fatal(a)
	}
}
func TestBadDNS(t *testing.T) {
	base := rr(response(), "service.example.com", 1, 60, []byte{10, 1, 2, 3})
	cases := map[string]func([]byte) []byte{
		"wrong_transaction": func(b []byte) []byte { b[1] = 43; return b }, "truncated": func(b []byte) []byte { return b[:len(b)-1] }, "compression_loop": func(b []byte) []byte { b[12] = 0xc0; b[13] = 12; return b }, "nxdomain": func(b []byte) []byte { b[3] = 0x83; return b }, "question_mismatch": func(b []byte) []byte { b[13] = 'x'; return b }, "too_many_answers": func(b []byte) []byte { binary.BigEndian.PutUint16(b[6:], 513); return b }, "fakeip": func(b []byte) []byte { copy(b[len(b)-4:], []byte{198, 19, 0, 1}); return b },
	}
	for n, f := range cases {
		t.Run(n, func(t *testing.T) {
			if _, e := Parse(f(append([]byte{}, base...)), 42, "service.example.com", "10.1.0.53", time.Now()); e == nil {
				t.Fatal("bad response granted a lease")
			}
		})
	}
}
func TestTTLZeroCapAndDuplicateMinimum(t *testing.T) {
	for _, ttl := range []uint32{0, 900} {
		b := rr(response(), "service.example.com", 1, ttl, []byte{10, 1, 2, 3})
		a, e := Parse(b, 42, "service.example.com", "10.1.0.53", time.Now())
		if ttl == 0 {
			if e == nil {
				t.Fatal("zero TTL retained")
			}
		} else if e != nil || a[0].TTL != 300 {
			t.Fatal(a, e)
		}
	}
	b := rr(response(), "service.example.com", 1, 90, []byte{10, 1, 2, 3})
	b = rr(b, "service.example.com", 1, 5, []byte{10, 1, 2, 3})
	a, e := Parse(b, 42, "service.example.com", "10.1.0.53", time.Now())
	if e != nil || a[0].TTL != 5 {
		t.Fatal("duplicate extended lease", a, e)
	}
}

func TestDuplicateZeroTTLCannotExtendAuthorization(t *testing.T) {
	for _, ttls := range [][]uint32{{0, 60}, {60, 0}} {
		b := response()
		for _, ttl := range ttls {
			b = rr(b, "service.example.com", 1, ttl, []byte{10, 1, 2, 3})
		}
		if _, e := Parse(b, 42, "service.example.com", "10.1.0.53", time.Now()); e == nil {
			t.Fatal("zero TTL duplicate granted a lease", ttls)
		}
	}
}

func TestMalformedCNAMEGraph(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"self_cycle": func(b []byte) []byte { return rr(b, "service.example.com", 5, 30, dnsName("service.example.com")) },
		"cycle_with_address": func(b []byte) []byte {
			b = rr(b, "service.example.com", 5, 30, dnsName("alias.example.com"))
			b = rr(b, "alias.example.com", 5, 30, dnsName("service.example.com"))
			return rr(b, "alias.example.com", 1, 30, []byte{10, 1, 2, 3})
		},
		"conflicting_aliases": func(b []byte) []byte {
			b = rr(b, "service.example.com", 5, 30, dnsName("alias.example.com"))
			b = rr(b, "service.example.com", 5, 30, dnsName("other.example.com"))
			return rr(b, "alias.example.com", 1, 30, []byte{10, 1, 2, 3})
		},
		"mixed_cname_a": func(b []byte) []byte {
			b = rr(b, "service.example.com", 5, 30, dnsName("alias.example.com"))
			return rr(b, "service.example.com", 1, 30, []byte{10, 1, 2, 3})
		},
	}
	for label, makeReply := range cases {
		t.Run(label, func(t *testing.T) {
			if _, e := Parse(makeReply(response()), 42, "service.example.com", "10.1.0.53", time.Now()); e == nil {
				t.Fatal("malformed CNAME authorized")
			}
		})
	}
}

func TestQueryCancellationInterruptsAcceptedConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	accepted := make(chan struct{})
	done := make(chan error, 1)
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		h := make([]byte, 2)
		if _, e := io.ReadFull(server, h); e != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(h))
		if _, e := io.ReadFull(server, q); e != nil {
			return
		}
		close(accepted)
	}()
	go func() {
		_, err := Query(ctx, func(context.Context, string, string) (net.Conn, error) { return client, nil }, "10.1.0.53", "service.example.com")
		done <- err
	}()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("query did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled query succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled query blocked on read")
	}
}
func TestQueryUsesOnlyExplicitBoundResolver(t *testing.T) {
	called := 0
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		called++
		if network != "tcp4" || address != "10.1.0.53:53" {
			t.Fatal(network, address)
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			h := make([]byte, 2)
			io.ReadFull(server, h)
			q := make([]byte, binary.BigEndian.Uint16(h))
			io.ReadFull(server, q)
			b := rr(response(), "service.example.com", 1, 10, []byte{10, 1, 2, 3})
			copy(b[:2], q[:2])
			binary.BigEndian.PutUint16(h, uint16(len(b)))
			server.Write(append(h, b...))
		}()
		return client, nil
	}
	a, e := Query(context.Background(), dial, "10.1.0.53", "service.example.com")
	if e != nil || len(a) != 1 || called != 1 {
		t.Fatal(a, e, called)
	}
}
func FuzzParseDoesNotPanic(f *testing.F) {
	f.Add(rr(response(), "service.example.com", 1, 10, []byte{10, 1, 2, 3}))
	f.Add([]byte{0xc0, 0})
	f.Fuzz(func(t *testing.T, b []byte) { Parse(b, 42, "service.example.com", "10.1.0.53", time.Unix(1, 0)) })
}
