package policy

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) Config {
	t.Helper()
	b, e := os.ReadFile("../../examples/policy.json")
	if e != nil {
		t.Fatal(e)
	}
	c, e := Decode(b)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func nodes() []Node {
	return []Node{{"type": "vless", "server": "203.0.113.7", "port": 443, "uuid": "11111111-1111-1111-1111-111111111111", "tls": true}}
}
func TestPolicyValidation(t *testing.T) {
	cases := map[string]func(*Config){
		"wildcard":            func(c *Config) { c.Company.Domains[0] = "*.example.com" },
		"uppercase":           func(c *Config) { c.Company.Domains[0] = "EXAMPLE.com" },
		"domain_overlap":      func(c *Config) { c.Personal.Domains = append(c.Personal.Domains, c.Company.Domains[0]) },
		"wide_cidr":           func(c *Config) { c.Company.CIDRs = []string{"10.0.0.0/8"} },
		"cidr_overlap":        func(c *Config) { c.Company.CIDRs = []string{"10.1.2.0/24"}; c.Personal.CIDRs = []string{"10.1.2.3/32"} },
		"fake_ip":             func(c *Config) { c.Company.CIDRs = []string{"198.19.0.0/24"} },
		"ipv6":                func(c *Config) { c.Company.CIDRs = []string{"2001:db8::/64"} },
		"vpn_userinfo":        func(c *Config) { c.VPN.Server = "https://secret@vpn.example.com/" },
		"vpn_port":            func(c *Config) { c.VPN.Server = "https://vpn.example.com:99999" },
		"probe_port":          func(c *Config) { c.Probes[0].URL = "https://gateway.corp.example.com:0/" },
		"probe_unapproved":    func(c *Config) { c.Probes[0].URL = "https://unapproved.example.com/" },
		"dns_fallback":        func(c *Config) { c.Company.DNS = []string{"https://resolver.example.com/dns-query"} },
		"personal_dns_domain": func(c *Config) { c.Personal.DNS = []string{"https://resolver.example.com/dns-query"} },
		"port_collision":      func(c *Config) { c.Ports.Proxy = c.Ports.DNS },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := fixture(t)
			mutate(&c)
			if c.Validate() == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}
func TestStrictJSON(t *testing.T) {
	c := fixture(t)
	b, _ := json.Marshal(c)
	for _, bad := range [][]byte{append(b, []byte(" {}")...), []byte(strings.Replace(string(b), `"version":1`, `"version":1,"rules":[]`, 1))} {
		if _, e := Decode(bad); e == nil {
			t.Fatal("unknown or extra policy accepted")
		}
	}
}
func TestCompileIsolation(t *testing.T) {
	c := fixture(t)
	out, e := Compile(c, nodes(), Binding{"en5", "utun32", "utun33", 19091}, strings.Repeat("s", 32))
	if e != nil {
		t.Fatal(e)
	}
	rules := out["rules"].([]string)
	if rules[len(rules)-1] != "MATCH,PHYSICAL" {
		t.Fatal("default exit changed")
	}
	groups := out["proxy-groups"].([]any)
	for _, group := range groups {
		g := group.(map[string]any)
		p := g["proxies"].([]string)
		if p[0] != "REJECT" {
			t.Fatal("group initially open")
		}
		for _, v := range p {
			if v == "DIRECT" || v == "PHYSICAL" {
				t.Fatal("fallback escape")
			}
		}
	}
	dns := out["dns"].(map[string]any)
	p := dns["nameserver-policy"].(map[string]any)
	if got := p[c.Company.Domains[0]].([]string)[0]; !strings.HasSuffix(got, "#CORP") {
		t.Fatal(got)
	}
	if out["tun"].(map[string]any)["enable"] != false {
		t.Fatal("compile enabled TUN")
	}
	proxy := out["proxies"].([]any)[2].(Node)
	if proxy["interface-name"] != "en5" {
		t.Fatal("physical endpoint not bound")
	}
	c.Company.CIDRs = []string{"203.0.113.0/24"}
	if _, e = Compile(c, nodes(), Binding{"en5", "utun32", "utun33", 19091}, strings.Repeat("s", 32)); e == nil {
		t.Fatal("control/business overlap accepted")
	}
}
func TestSubscriptionCannotSupplyPolicy(t *testing.T) {
	n, e := ImportNodes([]byte(`rules: ["MATCH,evil"]
dns: {nameserver: ["evil"]}
proxies:
- {name: "evil", type: vless, server: "203.0.113.7", port: 443, uuid: "11111111-1111-1111-1111-111111111111", tls: true, dialer-proxy: "evil", interface-name: "utun0"}
`))
	if e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"dialer-proxy", "interface-name", "rules", "dns"} {
		if _, ok := n[0][key]; ok {
			t.Fatalf("inherited %s", key)
		}
	}
	if n[0]["name"] != "P001" {
		t.Fatal("name was inherited")
	}
	for _, mutate := range []func(Node){func(n Node) { n["server"] = "https://node.example.com/" }, func(n Node) { n["skip-cert-verify"] = true }, func(n Node) { n["type"] = "direct" }, func(n Node) { delete(n, "uuid") }} {
		v := nodes()
		mutate(v[0])
		if _, e := SanitizeNodes(v); e == nil {
			t.Fatal("unsafe node accepted")
		}
	}
}

func TestLocalizedWindowsInterfaceBindings(t *testing.T) {
	c := fixture(t)
	for _, alias := range []string{"Wi-Fi", "以太网 2", "Local Area Connection", "en5"} {
		result, e := Compile(c, nodes(), Binding{Physical: alias, VPN: "NetLaunch-VPN", TUN: "NetLaunch-TUN", ControllerPort: 19091}, strings.Repeat("s", 32))
		if e != nil {
			t.Fatalf("valid interface %q: %v", alias, e)
		}
		if result["interface-name"] != alias {
			t.Fatal("interface alias changed during compilation")
		}
	}
	for _, alias := range []string{" Wi-Fi", "Wi-Fi ", "Wi-Fi\n", "Wi-Fi;stop", `Wi-Fi"`, "Wi-Fi&exit", "$(echo x)", "Wi-Fi%PATH%", "Wi-Fi!PATH!", "Wi-Fi\u202e"} {
		if ValidInterface(alias) {
			t.Fatalf("unsafe interface accepted: %q", alias)
		}
	}
	if _, e := Compile(c, nodes(), Binding{Physical: "Wi-Fi", VPN: "wi-fi", TUN: "NetLaunch-TUN", ControllerPort: 19091}, strings.Repeat("s", 32)); e == nil {
		t.Fatal("same Windows interface accepted as two exits")
	}
}
