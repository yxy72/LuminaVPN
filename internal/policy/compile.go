package policy

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type Binding struct {
	Physical       string `json:"physical"`
	VPN            string `json:"vpn"`
	TUN            string `json:"tun"`
	ControllerPort int    `json:"controller_port"`
}

func Compile(c Config, nodes []Node, b Binding, secret string) (map[string]any, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	nodes, err := SanitizeNodes(nodes)
	if err != nil {
		return nil, err
	}
	if !ValidInterface(b.Physical) || !ValidInterface(b.VPN) || !ValidInterface(b.TUN) || strings.EqualFold(b.Physical, b.VPN) || strings.EqualFold(b.VPN, b.TUN) || strings.EqualFold(b.Physical, b.TUN) {
		return nil, errors.New("distinct physical, VPN and TUN interfaces required")
	}
	if b.ControllerPort < 1024 || b.ControllerPort > 65535 || b.ControllerPort == c.Ports.Proxy || b.ControllerPort == c.Ports.DNS || len(secret) < 24 {
		return nil, errors.New("invalid local controller binding")
	}
	if err := ValidateEndpoints(c, nodes); err != nil {
		return nil, err
	}
	proxies := []any{map[string]any{"name": "CORP-BOUND", "type": "direct", "interface-name": b.VPN}, map[string]any{"name": "PHYSICAL", "type": "direct", "interface-name": b.Physical}}
	personal := []string{"REJECT"}
	for _, n := range nodes {
		n["interface-name"] = b.Physical
		proxies = append(proxies, n)
		personal = append(personal, n["name"].(string))
	}
	plan, err := RulePlan(c)
	if err != nil {
		return nil, err
	}
	rules := make([]string, 0, len(plan))
	for _, r := range plan {
		rules = append(rules, r.CoreRule())
	}
	dnsPolicy := map[string]any{}
	for i, ch := range []Channel{c.Company, c.Personal} {
		servers := []string{}
		for _, d := range ch.DNS {
			if i == 0 {
				servers = append(servers, "tcp://"+d+":53#CORP")
			} else {
				servers = append(servers, d+"#PERSONAL")
			}
		}
		for _, h := range ch.Domains {
			dnsPolicy[h] = servers
		}
	}
	// Pin local health targets before subscription rules, including direct probes.
	direct := []string{}
	for _, d := range c.DirectDNS {
		direct = append(direct, "udp://"+d+"#PHYSICAL")
	}
	for _, probe := range c.Probes {
		if probe.Channel == "direct" {
			u, _ := url.Parse(probe.URL)
			dnsPolicy[u.Hostname()] = direct
		}
	}
	// Exact company/local targets above win. Ordered local rules precede
	// subscribed rules. DNS's longest-match semantics must preserve rule order.
	type decision struct {
		index  int
		target string
	}
	suffixes := map[string]decision{}
	for index, r := range c.PersonalRules {
		if r.Type == "IP-CIDR" {
			continue
		}
		best := decision{index, r.Target}
		for domain := r.Value; domain != ""; {
			if old, ok := suffixes[domain]; ok && old.index < best.index {
				best = old
			}
			_, rest, found := strings.Cut(domain, ".")
			if !found {
				break
			}
			domain = rest
		}
		key := r.Value
		if r.Type == "DOMAIN-SUFFIX" {
			if _, exists := suffixes[r.Value]; !exists {
				suffixes[r.Value] = best
			}
			key = "+." + key
		}
		if _, exists := dnsPolicy[key]; exists {
			continue
		}
		servers := []string{}
		if best.target == "direct" {
			servers = direct
		} else {
			group := "PERSONAL"
			if best.target == "reject" {
				group = "REJECT"
			}
			for _, d := range c.Personal.DNS {
				servers = append(servers, d+"#"+group)
			}
		}
		dnsPolicy[key] = servers
	}
	return map[string]any{
		"mixed-port": c.Ports.Proxy, "allow-lan": false, "bind-address": "127.0.0.1", "mode": "rule", "log-level": "warning", "ipv6": false,
		"interface-name": b.Physical, "external-controller": fmt.Sprintf("127.0.0.1:%d", b.ControllerPort), "secret": secret,
		"geo-auto-update": false, "sniffer": map[string]any{"enable": false}, "profile": map[string]any{"store-selected": false, "store-fake-ip": false},
		"tun":     map[string]any{"enable": false, "device": b.TUN, "stack": "gvisor", "auto-route": true, "auto-detect-interface": false, "dns-hijack": []string{"any:53", "tcp://any:53"}},
		"dns":     map[string]any{"enable": true, "listen": fmt.Sprintf("127.0.0.1:%d", c.Ports.DNS), "ipv6": false, "enhanced-mode": "fake-ip", "fake-ip-range": "198.19.0.1/16", "use-hosts": false, "use-system-hosts": false, "nameserver": direct, "direct-nameserver": direct, "direct-nameserver-follow-policy": true, "nameserver-policy": dnsPolicy, "fallback": []string{}, "proxy-server-nameserver": direct},
		"proxies": proxies, "proxy-groups": []any{map[string]any{"name": "CORP", "type": "select", "proxies": []string{"REJECT", "CORP-BOUND"}}, map[string]any{"name": "PERSONAL", "type": "select", "proxies": personal}}, "rules": rules,
	}, nil
}
