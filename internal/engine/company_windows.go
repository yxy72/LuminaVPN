//go:build windows

package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"netlaunch/internal/companyproxy"
	"netlaunch/internal/dnswire"
	"netlaunch/internal/lease"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/socketbind"
	"netlaunch/internal/winnet"
)

type companyRuntime struct {
	run        string
	authority  *lease.Authority
	mu         sync.RWMutex
	session    *lease.Session
	generation string
	proxy      map[string]any
	done       chan error
}

func startCompany(ctx context.Context, run string) (*companyRuntime, error) {
	s, e := load(run)
	if e != nil {
		return nil, e
	}
	a, e := lease.NewCompany(s.Manifest.Config.Company, nil)
	if e != nil {
		return nil, e
	}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return nil, e
	}
	secret := make([]byte, 32)
	if _, e = rand.Read(secret); e != nil {
		l.Close()
		return nil, e
	}
	credentials := companyproxy.Credentials{Username: "company", Password: hex.EncodeToString(secret)}
	proxy, e := companyproxy.Proxy(l.Addr().String(), credentials)
	if e != nil {
		l.Close()
		return nil, e
	}
	// The core's global physical binding must not capture the local ingress.
	loopback, e := windowsLoopback()
	if e != nil {
		l.Close()
		return nil, e
	}
	proxy["interface-name"] = loopback
	c := &companyRuntime{run: run, authority: a, proxy: proxy, done: make(chan error, 1)}
	server, e := companyproxy.New(credentials, c.dial)
	if e != nil {
		l.Close()
		return nil, e
	}
	go func() { c.done <- server.Serve(ctx, l); a.Revoke() }()
	go c.maintain(ctx)
	return c, nil
}

func (c *companyRuntime) configure(config map[string]any) error {
	proxies, ok := config["proxies"].([]any)
	if !ok || len(proxies) == 0 {
		return errors.New("missing company proxy")
	}
	first, ok := proxies[0].(map[string]any)
	if !ok || first["name"] != "CORP-BOUND" {
		return errors.New("company proxy identity changed")
	}
	proxies[0] = c.proxy
	return nil
}

func (c *companyRuntime) current() (*lease.Session, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.session, c.generation
}
func (c *companyRuntime) revoke() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authority.Revoke()
	c.session = nil
	c.generation = ""
}

func (c *companyRuntime) maintain(ctx context.Context) {
	defer c.revoke()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s, e := load(c.run)
		if e != nil || guard(c.run, &s) != nil || !s.VPN.Bootstrap {
			c.revoke()
			continue
		}
		if e = validateVPN(s); e != nil {
			c.diagnostic("native_validation", e)
			c.revoke()
			continue
		}
		_, generation := c.current()
		if generation == s.VPN.Generation {
			continue
		}
		c.revoke()
		// Static grants and resolver routes must exist before any generation can
		// accept a request, including a profile with no domain grants.
		if e = c.prepare(ctx, s.VPN.Generation, "", nil); e != nil {
			c.diagnostic("static_routes", e)
			continue
		}
		c.mu.Lock()
		session := c.authority.Begin(ctx)
		c.session = session
		c.generation = s.VPN.Generation
		c.mu.Unlock()
		generation = s.VPN.Generation
		go session.MaintainPrepared(func(queryCtx context.Context, host string) ([]dnswire.Answer, error) {
			var last error
			for _, dns := range s.Manifest.Config.Company.DNS {
				a, e := dnswire.Query(queryCtx, windowsBound(s), dns, host)
				if e == nil {
					return a, nil
				}
				last = e
			}
			c.diagnostic("company_dns", last)
			return nil, last
		}, func(work context.Context, host string, a []dnswire.Answer) error {
			e := c.prepare(work, generation, host, a)
			if e != nil {
				c.diagnostic("domain_routes", e)
			}
			return e
		})
	}
}

func (c *companyRuntime) diagnostic(stage string, err error) {
	if platform.WindowsValidationBuild && err != nil {
		// Native trial evidence stays in administrator storage; never publish
		// resolver errors (which can contain private endpoints) in user status.
		_ = winWrite(c.run, "company-diagnostic-"+stage+".json", map[string]any{"stage": stage, "error": err.Error(), "time": time.Now()})
	}
}

func (c *companyRuntime) prepare(ctx context.Context, generation, host string, answers []dnswire.Answer) (result error) {
	started := time.Now()
	var lockWait, checks, routes time.Duration
	routeCount := 0
	defer func() {
		if !platform.WindowsValidationBuild {
			return
		}
		// Timing contains no domain, destination, or credential. Keep it local
		// to the protected run, outside the state lock being measured.
		if log, e := privateLog(c.run, "company-timing"); e == nil {
			_ = json.NewEncoder(log).Encode(map[string]any{"time": time.Now(), "total_ms": time.Since(started).Milliseconds(), "lock_wait_ms": lockWait.Milliseconds(), "checks_ms": checks.Milliseconds(), "routes_ms": routes.Milliseconds(), "route_count": routeCount, "success": result == nil})
			_ = log.Close()
		}
	}()
	return update(c.run, func(s *State) error {
		lockWait = time.Since(started)
		check := func() error {
			before := time.Now()
			defer func() { checks += time.Since(before) }()
			if e := ctx.Err(); e != nil {
				return e
			}
			if e := guard(c.run, s); e != nil {
				return e
			}
			if !s.VPN.Bootstrap || s.VPN.Generation != generation || !validVPN(*s) {
				return errors.New("company generation changed")
			}
			return nil
		}
		if e := check(); e != nil {
			return e
		}
		now := time.Now()
		next := []dnswire.Answer{}
		for _, a := range s.Leases {
			if a.Domain != host && now.Before(a.ExpiresAt) {
				next = append(next, a)
			}
		}
		for _, a := range answers {
			if !now.Before(a.ExpiresAt) {
				return lease.ErrDenied
			}
			next = append(next, a)
		}
		s.Leases = next
		wanted, prepare := companyRouteSets(s.Manifest.Config.Company, next, answers, host == "")
		m, e := networkManager(c.run)
		if e != nil {
			return e
		}
		journal, e := m.Store.Load()
		if e != nil {
			return e
		}
		if s.Windows.Guard == nil {
			return errors.New("company guard missing")
		}
		spec := *s.Windows.Guard
		for _, entry := range journal.Pairs {
			if entry.Guard == spec.Sublayer && !wanted[entry.VPN.Route.Prefix] {
				if e = check(); e != nil {
					return e
				}
				if e = m.RemoveCompanyRoute(spec, entry.VPN.Route.Prefix); e != nil {
					return e
				}
			}
		}
		for prefix := range prepare {
			if e = check(); e != nil {
				return e
			}
			before := time.Now()
			e = m.EnsureCompanyRoute(spec, s.Windows.TUNAdapter, prefix)
			routes += time.Since(before)
			routeCount++
			if e != nil {
				return e
			}
		}
		return check()
	})
}

// Retention covers every live domain, including shared addresses. A renewal
// prepares only its own RRset; other domains were prepared by their workers and
// every new socket still validates its native route pair and guard independently.
func companyRouteSets(company policy.Channel, live, refreshed []dnswire.Answer, bootstrap bool) (keep, prepare map[string]bool) {
	keep, prepare = map[string]bool{}, map[string]bool{}
	for _, dns := range company.DNS {
		keep[dns+"/32"] = true
	}
	for _, cidr := range company.CIDRs {
		keep[cidr] = true
	}
	for _, a := range live {
		keep[a.IP+"/32"] = true
	}
	if bootstrap {
		for prefix := range keep {
			prepare[prefix] = true
		}
	} else {
		for _, a := range refreshed {
			prepare[a.IP+"/32"] = true
		}
	}
	return
}

func (c *companyRuntime) state(generation string) (State, error) {
	s, e := load(c.run)
	if e != nil {
		return s, e
	}
	if e = guard(c.run, &s); e != nil {
		return s, e
	}
	if !s.VPN.Bootstrap || s.VPN.Generation != generation || !validVPN(s) {
		return s, lease.ErrRevoked
	}
	return s, nil
}

func (c *companyRuntime) dial(ctx context.Context, target string, port int) (conn net.Conn, result error) {
	defer func() { c.diagnostic("dial", result) }()
	session, generation := c.current()
	if session == nil {
		return nil, lease.ErrDenied
	}
	if _, e := c.state(generation); e != nil {
		return nil, e
	}
	return session.DialRenewingContext(ctx, target, port, func(ctx context.Context, network, address string) (net.Conn, error) {
		s, e := c.state(generation)
		if e != nil {
			return nil, e
		}
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		return windowsBound(s)(ctx, network, address)
	})
}

func (c *companyRuntime) ready() error {
	session, generation := c.current()
	if session == nil {
		return lease.ErrDenied
	}
	s, e := c.state(generation)
	if e != nil {
		return e
	}
	for _, host := range s.Manifest.Config.Company.Domains {
		if _, e := session.Lookup(host); e != nil {
			return e
		}
	}
	return nil
}

func windowsLoopback() (string, error) {
	items, e := winnet.Adapters()
	if e != nil {
		return "", e
	}
	for _, a := range items {
		if a.Type == 24 && a.Up {
			return a.Name, nil
		}
	}
	return "", errors.New("native loopback adapter unavailable")
}
func windowsBound(s State) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp4" {
			return nil, errors.New("company egress supports TCP IPv4 only")
		}
		addr, e := netip.ParseAddrPort(address)
		if e != nil {
			return nil, e
		}
		return socketbind.DialChecked(ctx, s.Windows.VPNAdapter.Index, s.VPN.Address, address, func() error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			live, e := load(s.Windows.PublicRun)
			if e != nil {
				return e
			}
			if live.VPN.Generation != s.VPN.Generation || !validVPN(live) {
				return lease.ErrRevoked
			}
			m, e := networkManager(s.Windows.PublicRun)
			if e != nil {
				return e
			}
			return m.CheckCompanyAddress(*live.Windows.Guard, addr.Addr().String())
		})
	}
}
