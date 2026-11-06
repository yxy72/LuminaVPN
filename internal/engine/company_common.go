//go:build darwin || windows

package engine

import (
	"context"
	"errors"
	"netlaunch/internal/lease"
	"sync"
)

type companyRuntime struct {
	run        string
	authority  *lease.Authority
	mu         sync.RWMutex
	session    *lease.Session
	generation string
	proxy      map[string]any
	done       chan error
	cancel     context.CancelFunc
}

func (c *companyRuntime) stop() {
	if c.cancel != nil {
		c.cancel()
	}
	c.revoke()
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
	if c.authority != nil {
		c.authority.Revoke()
	}
	c.session = nil
	c.generation = ""
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
