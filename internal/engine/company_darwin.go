//go:build darwin

package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"time"

	"netlaunch/internal/companyproxy"
	"netlaunch/internal/dnswire"
	"netlaunch/internal/lease"
	"netlaunch/internal/platform"
)

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
	proxy["interface-name"] = "lo0"
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
		if e != nil || guard(c.run, &s) != nil || !s.VPN.Bootstrap || !validVPN(s) {
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
				a, e := dnswire.Query(queryCtx, platform.BoundDialIdentity(s.VPN.Interface, s.VPN.Index), dns, host)
				if e == nil {
					return a, nil
				}
				last = e
			}
			return nil, last
		}, func(work context.Context, host string, a []dnswire.Answer) error {
			return c.prepare(work, generation, host, a)
		})
	}
}

func (c *companyRuntime) prepare(ctx context.Context, generation, host string, answers []dnswire.Answer) error {
	return update(c.run, func(s *State) error {
		check := func() error {
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
		wanted := map[string]bool{}
		for _, dns := range s.Manifest.Config.Company.DNS {
			wanted[dns+"/32"] = true
		}
		for _, cidr := range s.Manifest.Config.Company.CIDRs {
			wanted[cidr] = true
		}
		for _, a := range next {
			wanted[a.IP+"/32"] = true
		}
		for i, r := range s.Routes {
			if r.Route.Scoped && r.State != "removed" && !wanted[r.Route.Prefix] {
				if e := check(); e != nil {
					return e
				}
				if e := removeRoute(c.run, s, i); e != nil {
					return e
				}
			}
		}
		for prefix := range wanted {
			if e := check(); e != nil {
				return e
			}
			if e := ensureRoute(c.run, s, platform.Route{Prefix: prefix, Interface: s.VPN.Interface, Scoped: true}); e != nil {
				return e
			}
		}
		return check()
	})
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

func (c *companyRuntime) dial(ctx context.Context, target string, port int) (net.Conn, error) {
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
		addr, e := netip.ParseAddrPort(address)
		if e != nil {
			return nil, e
		}
		owned := false
		for _, r := range s.Routes {
			p, e := netip.ParsePrefix(r.Route.Prefix)
			if e != nil || !p.Contains(addr.Addr()) || r.State != "applied" || !r.Route.Scoped || r.InterfaceIndex != s.VPN.Index || r.Route.Interface != s.VPN.Interface {
				continue
			}
			actual, e := routeFind(r.Route)
			if e != nil {
				return nil, e
			}
			if actual != nil && sameRoute(*actual, r.Route) {
				owned = true
				break
			}
		}
		if !owned {
			return nil, errors.New("company route is not currently owned")
		}
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		return platform.BoundDialIdentity(s.VPN.Interface, s.VPN.Index)(ctx, network, address)
	})
}
