package lease

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestRenewingDialWaitsForNewAddressWithoutUsingExpiredGrant(t *testing.T) {
	_, s, clock := setup(t)
	publish(t, s, answer(clock, host, "192.0.2.1", 1))
	clock.advance(time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	called := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		c, err := s.DialRenewingContext(ctx, host, 443, func(_ context.Context, _ string, stringAddress string) (net.Conn, error) {
			called <- stringAddress
			client, server := net.Pipe()
			server.Close()
			return client, nil
		})
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	select {
	case target := <-called:
		t.Fatalf("expired grant dialed %s", target)
	case err := <-done:
		t.Fatalf("did not wait for renewal: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	publish(t, s, answer(clock, host, "192.0.2.2", 30))
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if target := <-called; target != "192.0.2.2:443" {
		t.Fatal("renewal used old address", target)
	}
}

func TestRenewingDialStopsOnCancellationRevokeAndItsOwnDeadline(t *testing.T) {
	for _, mode := range []string{"caller", "generation", "bounded"} {
		t.Run(mode, func(t *testing.T) {
			a, s, _ := setup(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "caller" {
				time.AfterFunc(75*time.Millisecond, cancel)
			}
			if mode == "generation" {
				time.AfterFunc(75*time.Millisecond, a.Revoke)
			}
			var calls atomic.Int32
			start := time.Now()
			c, err := s.DialRenewingContext(ctx, host, 443, func(context.Context, string, string) (net.Conn, error) {
				calls.Add(1)
				return nil, errors.New("must not dial")
			})
			want := context.DeadlineExceeded
			if mode == "caller" {
				want = context.Canceled
			} else if mode == "generation" {
				want = ErrRevoked
			}
			if c != nil || !errors.Is(err, want) || calls.Load() != 0 {
				t.Fatal("invalid wait outcome", c, err, calls.Load())
			}
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Fatal("wait exceeded bounded deadline", elapsed)
			}
		})
	}
}

func TestRenewingDialDoesNotRetryUnknownRawOrNativeFailure(t *testing.T) {
	_, s, clock := setup(t)
	publish(t, s, answer(clock, host, "192.0.2.1", 30))
	for _, target := range []string{"unknown.test", "192.0.2.1"} {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		c, err := s.DialRenewingContext(ctx, target, 443, func(context.Context, string, string) (net.Conn, error) {
			t.Error("unauthorized target reached native dial")
			return nil, nil
		})
		cancel()
		if c != nil || !errors.Is(err, ErrDenied) {
			t.Fatal("unauthorized target was retried", c, err)
		}
	}
	for _, nativeErr := range []error{errors.New("native guard changed"), context.DeadlineExceeded} {
		calls := 0
		_, err := s.DialRenewingContext(context.Background(), host, 443, func(context.Context, string, string) (net.Conn, error) {
			calls++
			return nil, nativeErr
		})
		if err != nativeErr || calls != 1 {
			t.Fatal("native failure retried while lease valid", err, calls)
		}
	}
}
