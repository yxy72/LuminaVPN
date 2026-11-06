//go:build windows

package engine

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"netlaunch/internal/companyproxy"
	"netlaunch/internal/policy"
)

// The local ingress identity and core routing remain fixed for the entire
// desktop run. Company failures/reconnects never reload the personal resolver
// or its fake-IP allocator. Once bound, retain the exact listener across local
// server restarts so another process cannot replace it between retries.
type desktopCompanyIngress struct {
	address     string
	credentials companyproxy.Credentials
	proxy       map[string]any
	listener    *net.TCPListener
	mu          sync.Mutex
	generation  uint64
}

func newDesktopCompanyIngress(cfg policy.Config, controller int) (*desktopCompanyIngress, error) {
	loopback, err := windowsLoopback()
	if err != nil {
		return nil, err
	}
	var random [34]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, err
	}
	port := 49152 + int(binary.BigEndian.Uint16(random[:2]))%16384
	for port == cfg.Ports.Proxy || port == cfg.Ports.DNS || port == controller {
		port = 49152 + (port-49152+1)%16384
	}
	i := &desktopCompanyIngress{address: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), credentials: companyproxy.Credentials{Username: "company", Password: hex.EncodeToString(random[2:])}}
	i.proxy, err = companyproxy.Proxy(i.address, i.credentials)
	if err != nil {
		return nil, err
	}
	i.proxy["interface-name"] = loopback
	return i, nil
}

type retainedCompanyListener struct {
	*net.TCPListener
	owner      *desktopCompanyIngress
	generation uint64
}

func (l retainedCompanyListener) Close() error {
	return l.owner.interruptLease(l.generation, func() error { return l.SetDeadline(time.Now()) })
}
func (i *desktopCompanyIngress) interruptLease(generation uint64, interrupt func() error) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if generation != i.generation {
		return nil
	}
	return interrupt()
}
func (i *desktopCompanyIngress) listen() (net.Listener, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.listener == nil {
		address, err := net.ResolveTCPAddr("tcp4", i.address)
		if err != nil {
			return nil, err
		}
		listener, err := net.ListenTCP("tcp4", address)
		if err != nil {
			return nil, err
		}
		i.listener = listener
	}
	if err := i.listener.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	i.generation++
	return retainedCompanyListener{i.listener, i, i.generation}, nil
}
func (i *desktopCompanyIngress) close() {
	if i != nil && i.listener != nil {
		i.mu.Lock()
		defer i.mu.Unlock()
		i.generation++
		_ = i.listener.Close()
	}
}
func (i *desktopCompanyIngress) inactive(run string) *companyRuntime {
	return &companyRuntime{run: run, proxy: i.proxy, done: make(chan error, 1)}
}

func stopDesktopCompany(c *companyRuntime) error {
	if c == nil {
		return nil
	}
	c.revoke() // Revoke all existing sockets before interrupting Accept.
	if c.cancel == nil {
		return nil
	}
	c.cancel()
	select {
	case <-c.done:
		c.cancel = nil
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("company ingress exit not confirmed")
	}
}

func startDesktopCompanyAt(ctx context.Context, run string, ingress *desktopCompanyIngress) (*companyRuntime, error) {
	if ingress == nil {
		return nil, errors.New("fixed desktop company ingress required")
	}
	if err := desktopCompanyMayStart(); err != nil {
		return nil, err
	}
	return startCompanyWithIngress(ctx, run, ingress)
}

func stableDesktopCompanyConfig(config map[string]any, company policy.Channel, proxy map[string]any) error {
	if proxy == nil || proxy["name"] != "CORP-BOUND" || proxy["type"] != "socks5" || proxy["server"] != "127.0.0.1" {
		return errors.New("fixed local company ingress unavailable")
	}
	config["proxies"] = append([]any{proxy}, config["proxies"].([]any)...)
	for _, raw := range config["proxy-groups"].([]any) {
		group := raw.(map[string]any)
		if group["name"] == "CORP" {
			group["proxies"] = []string{"REJECT", "CORP-BOUND"}
		}
	}
	first := map[string]bool{}
	for _, domain := range company.Domains {
		first["DOMAIN,"+domain+",REJECT"] = true
	}
	for _, prefix := range company.CIDRs {
		first["IP-CIDR,"+prefix+",REJECT,no-resolve"] = true
	}
	rules := config["rules"].([]string)
	for n, rule := range rules {
		if first[rule] {
			rules[n] = strings.Replace(rule, ",REJECT", ",CORP", 1)
			delete(first, rule)
		}
	}
	servers := []string{"rcode://refused"}
	if len(company.DNS) > 0 {
		servers = nil
		for _, dns := range company.DNS {
			servers = append(servers, "tcp://"+dns+":53#CORP")
		}
	}
	for _, domain := range company.Domains {
		config["dns"].(map[string]any)["nameserver-policy"].(map[string]any)[domain] = append([]string(nil), servers...)
	}
	return nil
}
