//go:build windows

package engine

import (
	"netlaunch/internal/dnswire"
	"netlaunch/internal/policy"
	"testing"
)

func TestCompanyRenewalRetainsOtherDomainsWithoutRepreparingThem(t *testing.T) {
	cfg := policy.Channel{DNS: []string{"192.0.2.53"}, CIDRs: []string{"198.51.100.0/24"}}
	live := []dnswire.Answer{{Domain: "other.test", IP: "192.0.2.8"}, {Domain: "renew.test", IP: "192.0.2.9"}, {Domain: "shared.test", IP: "192.0.2.9"}}
	keep, prepare := companyRouteSets(cfg, live, live[1:2], false)
	if len(keep) != 4 || !keep["192.0.2.8/32"] || !keep["192.0.2.53/32"] || !keep["198.51.100.0/24"] {
		t.Fatal("renewal would retire an unrelated route")
	}
	if len(prepare) != 1 || !prepare["192.0.2.9/32"] {
		t.Fatal("renewal prepares unrelated routes")
	}
	// Retiring renew.test cannot retire its address while shared.test owns it.
	keep, prepare = companyRouteSets(cfg, []dnswire.Answer{live[0], live[2]}, nil, false)
	if !keep["192.0.2.9/32"] || len(prepare) != 0 {
		t.Fatal("shared address lost")
	}
	keep, prepare = companyRouteSets(cfg, live, nil, true)
	if len(prepare) != len(keep) {
		t.Fatal("bootstrap omitted routes")
	}
	for p := range keep {
		if !prepare[p] {
			t.Fatal("bootstrap route missing")
		}
	}
}
