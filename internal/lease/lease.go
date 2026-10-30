// Package lease owns company address authorization independently of core DNS
// caches and health probes. It does not install routes or capture system traffic.
package lease

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"netlaunch/internal/dnswire"
	"netlaunch/internal/policy"
)

var (
	ErrRevoked    = errors.New("company generation was revoked")
	ErrDenied     = errors.New("no current exact-domain lease")
	ErrSuperseded = errors.New("DNS refresh was superseded")
)

type Resolve func(context.Context, string) ([]dnswire.Answer, error)

// Prepare installs native routes before publishing an address. It must honor
// cancellation and verify the VPN generation before each native mutation.
type Prepare func(context.Context, string, []dnswire.Answer) error

// Authority serializes VPN generations. Begin must be called after the native
// adapter validates a new interface identity; Revoke is required on network loss
// or resume, even when the SSID and interface name have stayed the same.
type Authority struct {
	mu      sync.Mutex
	domains []string
	now     func() time.Time
	current *Session
	cidrs   []netip.Prefix
	dns     map[string]bool
}

func New(domains []string, now func() time.Time) (*Authority, error) {
	return newAuthority(domains, now, false)
}
func newAuthority(domains []string, now func() time.Time, allowEmpty bool) (*Authority, error) {
	if (!allowEmpty && len(domains) == 0) || len(domains) > 128 {
		return nil, ErrDenied
	}
	seen := map[string]bool{}
	for _, host := range domains {
		if !policy.ValidDomain(host) || seen[host] {
			return nil, ErrDenied
		}
		seen[host] = true
	}
	if now == nil {
		now = time.Now
	}
	clock := now
	// Authorization expires in wall time across sleep, even on platforms whose
	// monotonic clock pauses. Resume still requires a separate generation revoke.
	return &Authority{domains: append([]string(nil), domains...), now: func() time.Time { return clock().Round(0) }}, nil
}

type entry struct {
	answers []dnswire.Answer
	version uint64
	cancel  context.CancelFunc
}

type Session struct {
	ctx         context.Context
	cancel      context.CancelFunc
	now         func() time.Time
	mu          sync.Mutex
	entries     map[string]*entry
	maintaining bool
	cidrs       []netip.Prefix
	dns         map[string]bool
}

func (a *Authority) Begin(parent context.Context) *Session {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.current != nil {
		a.current.cancel()
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Session{ctx: ctx, cancel: cancel, now: a.now, entries: map[string]*entry{}, cidrs: a.cidrs, dns: a.dns}
	for _, host := range a.domains {
		s.entries[host] = &entry{}
	}
	a.current = s
	return s
}

func (a *Authority) Revoke() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.current != nil {
		a.current.cancel()
	}
}

// Refresh does not hold the authority lock while resolving. A newer refresh or
// generation wins even if the old resolver ignores cancellation and returns late.
func (s *Session) Refresh(ctx context.Context, host string, resolve Resolve) error {
	return s.RefreshPrepared(ctx, host, resolve, nil)
}

func (s *Session) RefreshPrepared(ctx context.Context, host string, resolve Resolve, prepare Prepare) error {
	s.mu.Lock()
	e, allowed := s.entries[host]
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return ErrRevoked
	}
	if !allowed || resolve == nil {
		s.mu.Unlock()
		return ErrDenied
	}
	if e.cancel != nil {
		e.cancel()
	}
	work, cancel := context.WithTimeout(ctx, 3*time.Second)
	stop := context.AfterFunc(s.ctx, cancel)
	e.cancel = cancel
	e.version++
	version := e.version
	s.mu.Unlock()
	defer cancel()
	defer stop()
	answers, err := resolve(work, host)
	if err != nil {
		return err
	}
	if work.Err() != nil {
		return work.Err()
	}
	answers, err = validate(host, answers, s.now())
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return ErrRevoked
	}
	if e.version != version {
		s.mu.Unlock()
		return ErrSuperseded
	}
	if prepare != nil {
		// Withdraw a changed RRset before touching its old native routes. Unchanged
		// grants retain their original expiry while renewal prepares the same routes.
		if !sameAddresses(e.answers, answers) {
			e.answers = nil
		}
		s.mu.Unlock()
		err = prepare(work, host, append([]dnswire.Answer(nil), answers...))
		s.mu.Lock()
		if e.version != version {
			s.mu.Unlock()
			return ErrSuperseded
		}
		if err != nil {
			e.answers = nil
			s.mu.Unlock()
			return err
		}
	}
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return ErrRevoked
	}
	if work.Err() != nil {
		return work.Err()
	}
	answers, err = validate(host, answers, s.now())
	if err != nil {
		return err
	}
	e.answers = answers
	return nil
}

func sameAddresses(a, b []dnswire.Answer) bool {
	if len(a) != len(b) {
		return false
	}
	ips := map[string]bool{}
	for _, v := range a {
		ips[v.IP] = true
	}
	for _, v := range b {
		if !ips[v.IP] {
			return false
		}
	}
	return true
}

func validate(host string, answers []dnswire.Answer, now time.Time) ([]dnswire.Answer, error) {
	if len(answers) == 0 || len(answers) > 512 {
		return nil, ErrDenied
	}
	out := []dnswire.Answer{}
	seen := map[string]int{}
	for _, a := range answers {
		if _, err := policy.IPv4(a.IP); err != nil {
			return nil, ErrDenied
		}
		if _, err := policy.IPv4(a.DNS); err != nil {
			return nil, ErrDenied
		}
		if a.Domain != host || a.TTL == 0 || a.TTL > 300 || a.ResolvedAt.After(now) ||
			!now.Before(a.ExpiresAt) || a.ExpiresAt.After(a.ResolvedAt.Add(time.Duration(a.TTL)*time.Second)) {
			return nil, ErrDenied
		}
		if i, ok := seen[a.IP]; ok {
			if a.ExpiresAt.Before(out[i].ExpiresAt) {
				out[i] = a
			}
		} else {
			seen[a.IP] = len(out)
			out = append(out, a)
		}
	}
	return out, nil
}

// Lookup checks time synchronously. Worker delays cannot extend authorization.
// Returned slices are copies and cannot mutate the current grants.
func (s *Session) Lookup(host string) ([]dnswire.Answer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lookup(host)
}

func (s *Session) lookup(host string) ([]dnswire.Answer, error) {
	if s.ctx.Err() != nil {
		return nil, ErrRevoked
	}
	e, ok := s.entries[host]
	if !ok {
		return nil, ErrDenied
	}
	now := s.now()
	out := []dnswire.Answer{}
	for _, a := range e.answers {
		if now.Before(a.ExpiresAt) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, ErrDenied
	}
	return out, nil
}

// Maintain runs one renewal worker per exact domain, independently of slow
// application probes. Failure preserves a grant only until its existing expiry.
// The resolver must honor its context; stale results are rejected regardless.
func (s *Session) Maintain(resolve Resolve) error { return s.MaintainPrepared(resolve, nil) }
func (s *Session) MaintainPrepared(resolve Resolve, prepare Prepare) error {
	s.mu.Lock()
	if s.maintaining || resolve == nil {
		s.mu.Unlock()
		return errors.New("invalid renewal worker")
	}
	s.maintaining = true
	hosts := make([]string, 0, len(s.entries))
	for host := range s.entries {
		hosts = append(hosts, host)
	}
	s.mu.Unlock()
	var workers sync.WaitGroup
	for _, host := range hosts {
		workers.Add(1)
		go func(host string) {
			defer workers.Done()
			for s.ctx.Err() == nil {
				err := s.RefreshPrepared(s.ctx, host, resolve, prepare)
				delay := 250 * time.Millisecond
				if err == nil {
					if answers, e := s.Lookup(host); e == nil {
						delay = 150 * time.Second
						for _, a := range answers {
							if d := a.ExpiresAt.Sub(s.now()) / 2; d < delay {
								delay = d
							}
						}
						if delay < 10*time.Millisecond {
							delay = 10 * time.Millisecond
						}
					}
				}
				timer := time.NewTimer(delay)
				select {
				case <-s.ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}(host)
	}
	workers.Wait()
	return s.ctx.Err()
}

// DialContext grants a new TCP connection using an authorized literal address.
// It never consults system DNS or core DNS. The supplied dialer must enforce the
// native interface binding and route ownership; this package does not do that.
// Established streams survive TTL expiry, but are closed when a VPN generation
// is revoked. In-flight dials are checked again before being returned.
func (s *Session) DialContext(ctx context.Context, host string, port int, dial dnswire.Dial) (net.Conn, error) {
	if port < 1 || port > 65535 || dial == nil {
		return nil, ErrDenied
	}
	answers, err := s.grant(host, port)
	if err != nil {
		return nil, err
	}
	a := answers[0]
	work, cancel := context.WithTimeout(ctx, a.ExpiresAt.Sub(s.now()))
	stop := context.AfterFunc(s.ctx, cancel)
	defer cancel()
	defer stop()
	c, err := dial(work, "tcp4", net.JoinHostPort(a.IP, strconv.Itoa(port)))
	if err != nil {
		if c != nil {
			c.Close()
		}
		return nil, err
	}
	if c == nil {
		return nil, ErrDenied
	}
	// Register generation cancellation before checking again: a revoke racing
	// with this check either denies the dial or closes the returned connection.
	closeOnRevoke := context.AfterFunc(s.ctx, func() { _ = c.Close() })
	s.mu.Lock()
	current, checkErr := s.grantLocked(host, port)
	valid := false
	for _, latest := range current {
		if latest.IP == a.IP {
			valid = true
		}
	}
	if checkErr != nil || !valid || work.Err() != nil || !s.now().Before(a.ExpiresAt) {
		s.mu.Unlock()
		closeOnRevoke()
		_ = c.Close()
		return nil, ErrDenied
	}
	s.mu.Unlock()
	return &connection{Conn: c, stop: closeOnRevoke}, nil
}

type connection struct {
	net.Conn
	stop func() bool
}

func (c *connection) Close() error { c.stop(); return c.Conn.Close() }

// NewCompany also grants explicit company CIDRs and DNS bootstrap TCP/53. Raw
// addresses learned from a domain do not become independent IP authorizations.
func NewCompany(ch policy.Channel, now func() time.Time) (*Authority, error) {
	if len(ch.Domains)+len(ch.CIDRs) == 0 || len(ch.Domains)+len(ch.CIDRs) > 128 || len(ch.DNS) == 0 || len(ch.DNS) > 4 {
		return nil, ErrDenied
	}
	a, err := newAuthority(ch.Domains, now, len(ch.CIDRs) > 0)
	if err != nil {
		return nil, err
	}
	for _, raw := range ch.CIDRs {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() < 24 {
			return nil, ErrDenied
		}
		if _, err = policy.IPv4(p.Addr().String()); err != nil {
			return nil, err
		}
		a.cidrs = append(a.cidrs, p)
	}
	a.dns = map[string]bool{}
	for _, raw := range ch.DNS {
		if _, err := policy.IPv4(raw); err != nil {
			return nil, err
		}
		a.dns[raw] = true
	}
	return a, nil
}
func (s *Session) grant(host string, port int) ([]dnswire.Answer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.grantLocked(host, port)
}
func (s *Session) grantLocked(host string, port int) ([]dnswire.Answer, error) {
	if s.ctx.Err() != nil {
		return nil, ErrRevoked
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return s.lookup(host)
	}
	if _, err = policy.IPv4(host); err != nil {
		return nil, ErrDenied
	}
	allowed := port == 53 && s.dns[host]
	for _, p := range s.cidrs {
		allowed = allowed || p.Contains(ip)
	}
	if !allowed {
		return nil, ErrDenied
	}
	return []dnswire.Answer{{IP: host, ExpiresAt: s.now().Add(3 * time.Second)}}, nil
}
func (c *connection) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return errors.New("connection does not support half-close")
}
