package lease

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"netlaunch/internal/dnswire"
)

const host = "service.example.com"

type testClock struct {
	sync.Mutex
	t time.Time
}

func (c *testClock) now() time.Time          { c.Lock(); defer c.Unlock(); return c.t }
func (c *testClock) advance(d time.Duration) { c.Lock(); defer c.Unlock(); c.t = c.t.Add(d) }
func setup(t *testing.T, domains ...string) (*Authority, *Session, *testClock) {
	t.Helper()
	if len(domains) == 0 {
		domains = []string{host}
	}
	c := &testClock{t: time.Now()}
	a, err := New(domains, c.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Revoke)
	return a, a.Begin(context.Background()), c
}
func answer(c *testClock, domain, ip string, ttl uint32) dnswire.Answer {
	now := c.now()
	return dnswire.Answer{Domain: domain, IP: ip, DNS: "10.1.0.53", TTL: ttl, ResolvedAt: now, ExpiresAt: now.Add(time.Duration(ttl) * time.Second)}
}
func publish(t *testing.T, s *Session, answers ...dnswire.Answer) {
	t.Helper()
	if err := s.Refresh(context.Background(), answers[0].Domain, func(context.Context, string) ([]dnswire.Answer, error) { return answers, nil }); err != nil {
		t.Fatal(err)
	}
}
func TestExactExpiryAndFailedRenewal(t *testing.T) {
	_, s, c := setup(t)
	publish(t, s, answer(c, host, "10.1.2.3", 2))
	copy, _ := s.Lookup(host)
	copy[0].IP = "10.1.2.9"
	if got, _ := s.Lookup(host); got[0].IP != "10.1.2.3" {
		t.Fatal("mutable grants")
	}
	c.advance(time.Second)
	err := s.Refresh(context.Background(), host, func(context.Context, string) ([]dnswire.Answer, error) { return nil, errors.New("offline") })
	if err == nil {
		t.Fatal("failed refresh succeeded")
	}
	if _, err = s.Lookup(host); err != nil {
		t.Fatal("unexpired grant lost", err)
	}
	c.advance(time.Second)
	if _, err = s.Lookup(host); !errors.Is(err, ErrDenied) {
		t.Fatal("expiry boundary granted", err)
	}
	if _, err = s.Lookup("other." + host); !errors.Is(err, ErrDenied) {
		t.Fatal("suffix grant", err)
	}
}

func TestRotationAndRevokeRejectLateResults(t *testing.T) {
	a, s, c := setup(t)
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s.Refresh(context.Background(), host, func(context.Context, string) ([]dnswire.Answer, error) {
			close(started)
			<-release
			return []dnswire.Answer{answer(c, host, "10.1.2.3", 30)}, nil
		})
	}()
	<-started
	next := a.Begin(context.Background())
	publish(t, next, answer(c, host, "10.1.2.4", 30))
	close(release)
	if err := <-done; err == nil {
		t.Fatal("old generation republished")
	}
	if _, err := s.Lookup(host); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
	if got, err := next.Lookup(host); err != nil || got[0].IP != "10.1.2.4" {
		t.Fatal(got, err)
	}
}

func TestLaterRefreshWinsWithinSameGeneration(t *testing.T) {
	_, s, c := setup(t)
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s.Refresh(context.Background(), host, func(context.Context, string) ([]dnswire.Answer, error) {
			close(started)
			<-release
			return []dnswire.Answer{answer(c, host, "10.1.2.3", 30)}, nil
		})
	}()
	<-started
	publish(t, s, answer(c, host, "10.1.2.4", 30))
	close(release)
	if err := <-done; err == nil {
		t.Fatal("late refresh replaced newer answer")
	}
	got, err := s.Lookup(host)
	if err != nil || got[0].IP != "10.1.2.4" {
		t.Fatal(got, err)
	}
}

func TestRejectInvalidLeasePublication(t *testing.T) {
	_, s, c := setup(t)
	cases := map[string]func(*dnswire.Answer){
		"zero_ttl":     func(a *dnswire.Answer) { a.TTL = 0 },
		"expired":      func(a *dnswire.Answer) { a.ExpiresAt = c.now() },
		"extended":     func(a *dnswire.Answer) { a.ExpiresAt = a.ExpiresAt.Add(time.Second) },
		"future":       func(a *dnswire.Answer) { a.ResolvedAt = c.now().Add(time.Second) },
		"domain":       func(a *dnswire.Answer) { a.Domain = "other.example.com" },
		"ipv6":         func(a *dnswire.Answer) { a.IP = "::1" },
		"fakeip":       func(a *dnswire.Answer) { a.IP = "198.19.0.1" },
		"dns_hostname": func(a *dnswire.Answer) { a.DNS = "dns.example.com" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := answer(c, host, "10.1.2.3", 2)
			mutate(&a)
			if err := s.Refresh(context.Background(), host, func(context.Context, string) ([]dnswire.Answer, error) { return []dnswire.Answer{a}, nil }); err == nil {
				t.Fatal("invalid grant published")
			}
		})
	}
	if _, err := s.Lookup(host); err == nil {
		t.Fatal("invalid grant retained")
	}
}

func TestDialRejectsExpiredAndRotatedInFlightResults(t *testing.T) {
	for _, mode := range []string{"expiry", "rotation", "revoke", "caller_cancel"} {
		t.Run(mode, func(t *testing.T) {
			a, s, c := setup(t)
			publish(t, s, answer(c, host, "10.1.2.3", 2))
			client, peer := net.Pipe()
			defer peer.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			conn, err := s.DialContext(ctx, host, 8443, func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp4" || address != "10.1.2.3:8443" {
					t.Fatal(network, address)
				}
				switch mode {
				case "expiry":
					c.advance(2 * time.Second)
				case "rotation":
					publish(t, s, answer(c, host, "10.1.2.4", 2))
				case "revoke":
					a.Revoke()
				case "caller_cancel":
					cancel()
				}
				return client, nil
			})
			if err == nil || conn != nil {
				t.Fatal("invalid in-flight dial returned", conn, err)
			}
			peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatal("rejected socket left open", err)
			}
		})
	}
}

func TestEstablishedStreamClosesOnGenerationRevoke(t *testing.T) {
	a, s, c := setup(t)
	publish(t, s, answer(c, host, "10.1.2.3", 2))
	client, peer := net.Pipe()
	defer peer.Close()
	conn, err := s.DialContext(context.Background(), host, 443, func(context.Context, string, string) (net.Conn, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c.advance(2 * time.Second)
	// TTL expiration prevents new streams but doesn't terminate an existing one.
	go func() { _, _ = peer.Write([]byte("x")) }()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = io.ReadFull(conn, make([]byte, 1)); err != nil {
		t.Fatal("TTL closed established stream", err)
	}
	a.Revoke()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("revoked stream remains open", err)
	}
}

func TestIndependentRenewalAndCancellation(t *testing.T) {
	a, s, c := setup(t, host, "slow.example.com")
	fast := make(chan struct{}, 4)
	slow := make(chan struct{})
	done := make(chan error, 1)
	var once sync.Once
	go func() {
		done <- s.Maintain(func(ctx context.Context, domain string) ([]dnswire.Answer, error) {
			if domain == "slow.example.com" {
				once.Do(func() { close(slow) })
				<-ctx.Done()
				return nil, ctx.Err()
			}
			fast <- struct{}{}
			return []dnswire.Answer{answer(c, host, "10.1.2.3", 1)}, nil
		})
	}()
	select {
	case <-slow:
	case <-time.After(time.Second):
		t.Fatal("slow domain not started")
	}
	for i := 0; i < 2; i++ {
		select {
		case <-fast:
		case <-time.After(2 * time.Second):
			t.Fatal("slow domain blocked independent renewal")
		}
	}
	a.Revoke()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
}

func TestExpiredLeaseNeverInvokesDial(t *testing.T) {
	_, s, c := setup(t)
	publish(t, s, answer(c, host, "10.1.2.3", 1))
	c.advance(time.Second)
	_, err := s.DialContext(context.Background(), host, 443, func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("expired authorization reached dialer")
		return nil, nil
	})
	if !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
}
