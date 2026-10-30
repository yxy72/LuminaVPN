package policy

import (
	"reflect"
	"strings"
	"testing"
)

func TestNodeDomainBootstrapStaysPhysical(t *testing.T) {
	c := fixture(t)
	n := nodes()
	n[0]["server"] = "NODE.Example.COM."
	n[0]["servername"] = "tls.example.net"
	out, e := Compile(c, n, Binding{"en5", "utun32", "utun33", 19091}, strings.Repeat("s", 32))
	if e != nil {
		t.Fatal(e)
	}
	node := out["proxies"].([]any)[2].(Node)
	if node["server"] != "node.example.com" || node["servername"] != "tls.example.net" || node["interface-name"] != "en5" {
		t.Fatal("node identity or physical binding changed")
	}
	dns := out["dns"].(map[string]any)
	wanted := []string{}
	for _, server := range c.DirectDNS {
		wanted = append(wanted, "udp://"+server+"#PHYSICAL")
	}
	if !reflect.DeepEqual(dns["proxy-server-nameserver"], wanted) {
		t.Fatal("node bootstrap is not explicitly physical")
	}
	if _, exists := dns["nameserver-policy"].(map[string]any)["node.example.com"]; exists {
		t.Fatal("node domain gained business authorization")
	}
}
func TestNodeControlCannotUseBusinessNamesOrResolver(t *testing.T) {
	c := fixture(t)
	for _, server := range []string{c.Company.Domains[0], c.Personal.Domains[0], c.Company.DNS[0], "127.0.0.1", "::1", "node.example.com:443"} {
		n := nodes()
		n[0]["server"] = server
		if _, e := Compile(c, n, Binding{"en5", "utun32", "utun33", 19091}, strings.Repeat("s", 32)); e == nil {
			t.Fatal("unsafe endpoint accepted", server)
		}
	}
}
func TestMixedSubscriptionReportsEveryOmission(t *testing.T) {
	data := []byte(`proxies:
- {type: vless, server: node.example.com, port: 443, uuid: private-value, tls: true, dialer-proxy: CORP}
- {type: hysteria2, server: node2.example.com, port: 443, password: private-value, skip-cert-verify: true}
- {type: ss, server: 203.0.113.7, port: 443, password: private-value}
- {type: vless, server: 203.0.113.8, port: 443, uuid: private-value, tls: true}
`)
	n, issues, e := ImportSupportedNodes(data)
	if e != nil {
		t.Fatal(e)
	}
	if len(n) != 2 || len(issues) != 2 || issues[0].Index != 2 || issues[1].Index != 3 || n[1]["name"] != "P002" {
		t.Fatal("mixed import accounting differs")
	}
	if _, ok := n[0]["dialer-proxy"]; ok {
		t.Fatal("inherited routing chain")
	}
	for _, issue := range issues {
		if strings.Contains(issue.Reason, "private-value") {
			t.Fatal("credential in import report")
		}
	}
}
