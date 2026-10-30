package winnet

import "testing"

func TestDNSRecoveryPreservesAutomaticAndProfileSettings(t *testing.T) {
	a := DNSSettings{NameServers: "1.1.1.1 8.8.8.8", ProfileNameServers: "9.9.9.9"}
	b := DNSSettings{NameServers: "1.1.1.1,8.8.8.8", ProfileNameServers: "9.9.9.9"}
	if !SameDNS(a, b) {
		t.Fatal("equivalent DNS lists differ")
	}
	if SameDNS(DNSSettings{}, DNSSettings{NameServers: "192.168.1.1"}) {
		t.Fatal("DHCP response mistaken for configured static DNS")
	}
	b.ProfileNameServers = ""
	if SameDNS(a, b) {
		t.Fatal("external profile change missed")
	}
	for _, s := range []string{"1.1.1.1;malformed", "::1", "0.0.0.0", "224.0.0.1", "dns.example.com"} {
		if (DNSSettings{NameServers: s}).Validate() == nil {
			t.Fatal("invalid DNS", s)
		}
	}
}
