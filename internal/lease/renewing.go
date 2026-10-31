package lease

import (
	"context"
	"errors"
	"net"
	"time"

	"netlaunch/internal/dnswire"
)

// DialRenewingContext permits a bounded wait for an exact domain's next grant.
// Cached DNS answers can count down to zero before the resolver returns a fresh
// RRset. Waiting does not extend a grant: every attempt uses DialContext, which
// checks the original TTL, generation and current RRset before and after dialing.
// Literal addresses and unknown domains retain immediate refusal semantics.
func (s *Session) DialRenewingContext(ctx context.Context, host string, port int, dial dnswire.Dial) (net.Conn, error) {
	c, err := s.DialContext(ctx, host, port, dial)
	if err == nil || port < 1 || port > 65535 || dial == nil || ctx.Err() != nil {
		return c, err
	}
	s.mu.Lock()
	_, exact := s.entries[host]
	s.mu.Unlock()
	if !exact || !s.renewalDialError(host, err) {
		return c, err
	}
	wait, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return nil, ErrRevoked
		case <-wait.Done():
			return nil, wait.Err()
		case <-ticker.C:
		}
		c, err = s.DialContext(wait, host, port, dial)
		if err == nil || !s.renewalDialError(host, err) {
			return c, err
		}
	}
}

func (s *Session) renewalDialError(host string, err error) bool {
	if errors.Is(err, ErrDenied) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		_, current := s.Lookup(host)
		return errors.Is(current, ErrDenied)
	}
	return false
}
