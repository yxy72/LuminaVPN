package policy

import "testing"

func TestProbePurposeDefaultsAndExplicitExpectations(t *testing.T) {
	for _, channel := range []string{"company", "personal", "direct"} {
		p := Probe{Channel: channel}
		if p.AcceptsStatus(503) != (channel != "personal") || !p.AcceptsStatus(204) {
			t.Fatal(channel)
		}
		p.Purpose = "path"
		if !p.AcceptsStatus(403) || !p.AcceptsStatus(503) || p.AcceptsStatus(101) {
			t.Fatal(p)
		}
		p.Purpose, p.ExpectedStatus = "service", []int{204, 401}
		if !p.AcceptsStatus(204) || !p.AcceptsStatus(401) || p.AcceptsStatus(200) || p.AcceptsStatus(503) {
			t.Fatal(p)
		}
	}
	for _, p := range []Probe{
		{Purpose: "wrong"}, {Purpose: "path", ExpectedStatus: []int{204}},
		{Purpose: "service", ExpectedStatus: []int{101}}, {Purpose: "service", ExpectedStatus: []int{600}},
		{Purpose: "service", ExpectedStatus: []int{204, 204}},
	} {
		cfg := fixture(t)
		p.URL, p.Channel = cfg.Probes[0].URL, cfg.Probes[0].Channel
		cfg.Probes[0] = p
		if cfg.Validate() == nil {
			t.Fatal("invalid purpose/expectation accepted", p)
		}
	}
}
