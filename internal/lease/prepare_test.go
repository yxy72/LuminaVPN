package lease

import (
	"context"
	"errors"
	"testing"
	"time"

	"netlaunch/internal/dnswire"
	"netlaunch/internal/policy"
)

func TestRoutePreparationWithdrawsOldAddressBeforePublication(t *testing.T) {
	_, s, c := setup(t)
	publish(t, s, answer(c, host, "10.1.2.3", 30))
	prepared := false
	err := s.RefreshPrepared(context.Background(), host, func(context.Context, string) ([]dnswire.Answer, error) {
		return []dnswire.Answer{answer(c, host, "10.1.2.4", 30)}, nil
	}, func(_ context.Context, domain string, a []dnswire.Answer) error {
		if _, err := s.Lookup(host); !errors.Is(err, ErrDenied) {
			t.Error("old address admitted while routes change", err)
		}
		if domain != host || len(a) != 1 || a[0].IP != "10.1.2.4" {
			t.Error(domain, a)
		}
		prepared = true
		return nil
	})
	if err != nil || !prepared {
		t.Fatal(err)
	}
	if a, err := s.Lookup(host); err != nil || a[0].IP != "10.1.2.4" {
		t.Fatal(a, err)
	}
}

func TestFailedOrExpiredPreparationCannotGrant(t *testing.T) {
	for _, mode := range []string{"failed", "expired", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			a, s, c := setup(t)
			publish(t, s, answer(c, host, "10.1.2.3", 30))
			err := s.RefreshPrepared(context.Background(), host, func(context.Context, string) ([]dnswire.Answer, error) {
				return []dnswire.Answer{answer(c, host, "10.1.2.4", 1)}, nil
			}, func(context.Context, string, []dnswire.Answer) error {
				switch mode {
				case "failed":
					return errors.New("route conflict")
				case "expired":
					c.advance(time.Second)
				case "revoked":
					a.Revoke()
				}
				return nil
			})
			if err == nil {
				t.Fatal("invalid preparation published")
			}
			if _, err = s.Lookup(host); err == nil {
				t.Fatal("old address reopened")
			}
		})
	}
}

func TestStaticGrantsDoNotExpandDomainAuthorization(t *testing.T) {
	c := &testClock{t: time.Now()}
	a, err := NewCompany(policy.Channel{Domains: []string{host}, CIDRs: []string{"10.20.30.0/24"}, DNS: []string{"10.1.0.53"}}, c.now)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Revoke()
	s := a.Begin(context.Background())
	publish(t, s, answer(c, host, "10.1.2.3", 30))
	for _, tc := range []struct {
		target  string
		port    int
		allowed bool
	}{{"10.1.0.53", 53, true}, {"10.1.0.53", 443, false}, {"10.20.30.1", 443, true}, {"10.20.31.1", 443, false}, {"10.1.2.3", 443, false}, {host, 443, true}} {
		_, err := s.grant(tc.target, tc.port)
		if (err == nil) != tc.allowed {
			t.Fatal(tc, err)
		}
	}
	a.Revoke()
	if _, err := s.grant("10.1.0.53", 53); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
}

func TestNativePreparationHasSeparateBudgetWithoutExtendingTTL(t *testing.T) {
	_, s, c := setup(t)
	a := answer(c, host, "192.0.2.8", 30)
	err := s.RefreshPrepared(context.Background(), host, func(ctx context.Context, _ string) ([]dnswire.Answer, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 3*time.Second {
			t.Fatal("resolver budget increased")
		}
		return []dnswire.Answer{a}, nil
	}, func(ctx context.Context, _ string, _ []dnswire.Answer) error {
		select {
		case <-time.After(3100 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	if err != nil {
		t.Fatal("native work inherited resolver deadline", err)
	}
	got, err := s.Lookup(host)
	if err != nil || len(got) != 1 || !got[0].ExpiresAt.Equal(a.ExpiresAt) {
		t.Fatal("TTL changed during preparation", err)
	}
}

func TestPreparationTimeoutCannotGrantEvenIfCallbackIgnoresIt(t *testing.T) {
	_, s, c := setup(t)
	err := s.RefreshPrepared(context.Background(), host, func(context.Context, string) ([]dnswire.Answer, error) {
		return []dnswire.Answer{answer(c, host, "192.0.2.8", 1)}, nil
	}, func(ctx context.Context, _ string, _ []dnswire.Answer) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > time.Second {
			t.Fatal("preparation outlives answer TTL")
		}
		<-ctx.Done()
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("ignored preparation deadline", err)
	}
	if _, err = s.Lookup(host); err == nil {
		t.Fatal("expired preparation authorized")
	}
}
