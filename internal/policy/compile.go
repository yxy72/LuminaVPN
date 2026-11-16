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
	return CompileWithIntent(c, nodes, b, secret, DefaultIntent())
}

func CompileWithIntent(c Config, nodes []Node, b Binding, secret string, intent ChannelIntent) (map[string]any, error) {
	return compile(c, nodes, b, secret, intent, false)
}

// CompilePersonalFallback leaves PERSONAL at REJECT for the desktop to grant
// temporary direct access. The same selector controls personal traffic and its DNS.
func CompilePersonalFallback(c Config, nodes []Node, b Binding, secret string, intent ChannelIntent) (map[string]any, error) {
	if !intent.Personal {
		return nil, errors.New("temporary fallback requires enabled personal intent")
	}
	return compile(c, nodes, b, secret, intent, true)
}

func compile(c Config, nodes []Node, b Binding, secret string, intent ChannelIntent, personalFallback bool) (map[string]any, error) {
	if err := c.ValidateForIntent(intent); err != nil {
		return nil, err
	}
	var err error
	if len(nodes) != 0 || intent.Personal {
		nodes, err = SanitizeNodes(nodes)
		if err != nil {
			return nil, err
		}
	}
	if !ValidInterface(b.Physical) || !ValidInterface(b.VPN) || !ValidInterface(b.TUN) || strings.EqualFold(b.Physical, b.VPN) || strings.EqualFold(b.VPN, b.TUN) || strings.EqualFold(b.Physical, b.TUN) {
		return nil, errors.New("distinct physical, VPN and TUN interfaces required")
	}
	if b.ControllerPort < 1024 || b.ControllerPort > 65535 || b.ControllerPort == c.Ports.Proxy || b.ControllerPort == c.Ports.DNS || len(secret) < 24 {
		return nil, errors.New("invalid local controller binding")
	}
	if err := validateEndpoints(c, nodes, intent.Company); err != nil {
		return nil, err
	}
	proxies := []any{map[string]any{"name": "CORP-BOUND", "type": "direct", "interface-name": b.VPN}, map[string]any{"name": "PHYSICAL", "type": "direct", "interface-name": b.Physical}}
	personal := []string{"REJECT"}
	for _, n := range nodes {
		n["interface-name"] = b.Physical
		proxies = append(proxies, n)
		personal = append(personal, n["name"].(string))
	}
	plan, err := RulePlanForIntent(c, intent)
	if err != nil {
		return nil, err
	}
	rules := make([]string, 0, len(plan))
	for _, r := range plan {
		rules = append(rules, r.CoreRule())
	}
	dnsPolicy := map[string]any{}
	corporate := []string{}
	for _, server := range c.Company.DNS {
		corporate = append(corporate, "tcp://"+server+":53#CORP")
	}
	if !intent.Company {
		corporate = []string{"rcode://refused"}
	}
	for _, domain := range c.Company.Domains {
		dnsPolicy[domain] = corporate
	}
	direct := []string{}
	for _, server := range c.DirectDNS {
		direct = append(direct, "udp://"+server+"#PHYSICAL")
	}
	personalDNS, rejectedDNS := []string{}, []string{}
	for _, server := range c.Personal.DNS {
		personalDNS = append(personalDNS, server+"#PERSONAL")
		rejectedDNS = append(rejectedDNS, server+"#REJECT")
	}
	switch {
	case personalFallback:
		personalDNS = make([]string, 0, len(c.DirectDNS))
		for _, server := range c.DirectDNS {
			personalDNS = append(personalDNS, "udp://"+server+"#PERSONAL")
		}
	case !intent.Personal:
		personalDNS = direct
	}
	for _, domain := range c.Personal.Domains {
		dnsPolicy[domain] = personalDNS
	}
	// Pin local health targets before subscription rules, including direct probes.
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
	overrides, _ := c.environmentRules(intent)
	dnsRules := append(append([]Rule(nil), overrides...), c.PersonalRules...)
	for index, r := range dnsRules {
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
		_, exists := dnsPolicy[key]
		if exists && !(index < len(overrides) && !c.IsCompany(r.Value)) {
			continue
		}
		switch best.target {
		case "direct":
			dnsPolicy[key] = direct
		case "reject":
			dnsPolicy[key] = rejectedDNS
		case "personal":
			dnsPolicy[key] = personalDNS
		}
	}
	// Exact personal DNS entries must follow the same first-match environment
	// override as the traffic rules, even when that override is a suffix.
	if intent.Environment != "" {
		for _, domain := range c.Personal.Domains {
			for _, r := range overrides {
				matches := r.Type == "DOMAIN" && domain == r.Value || r.Type == "DOMAIN-SUFFIX" && (domain == r.Value || strings.HasSuffix(domain, "."+r.Value))
				if !matches {
					continue
				}
				if r.Target == "direct" {
					dnsPolicy[domain] = direct
				} else {
					dnsPolicy[domain] = personalDNS
				}
				break
			}
		}
	}
	if !intent.Personal || personalFallback {
		personal = []string{"REJECT", "PHYSICAL"}
	}
	personalGroup := map[string]any{"name": "PERSONAL", "type": "select", "proxies": personal}
	if personalFallback {
		personalGroup["lumina-fallback-lease"] = true
	}
	corp := []string{"REJECT", "CORP-BOUND"}
	if !intent.Company {
		corp = []string{"REJECT"}
		proxies = proxies[1:]
	}
	return map[string]any{
		"mixed-port": c.Ports.Proxy, "allow-lan": false, "bind-address": "127.0.0.1", "mode": "rule", "log-level": "warning", "ipv6": false,
		"interface-name": b.Physical, "external-controller": fmt.Sprintf("127.0.0.1:%d", b.ControllerPort), "secret": secret,
		"geo-auto-update": false, "sniffer": map[string]any{"enable": false}, "profile": map[string]any{"store-selected": false, "store-fake-ip": false},
		"tun":     map[string]any{"enable": false, "device": b.TUN, "stack": "gvisor", "auto-route": true, "auto-detect-interface": false, "dns-hijack": []string{"any:53", "tcp://any:53"}},
		"dns":     map[string]any{"enable": true, "listen": fmt.Sprintf("127.0.0.1:%d", c.Ports.DNS), "ipv6": false, "enhanced-mode": "fake-ip", "fake-ip-range": "198.19.0.1/16", "use-hosts": false, "use-system-hosts": false, "nameserver": direct, "direct-nameserver": direct, "direct-nameserver-follow-policy": true, "nameserver-policy": dnsPolicy, "fallback": []string{}, "proxy-server-nameserver": direct},
		"proxies": proxies, "proxy-groups": []any{map[string]any{"name": "CORP", "type": "select", "proxies": corp}, personalGroup}, "rules": rules,
	}, nil
}
