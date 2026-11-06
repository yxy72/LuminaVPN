package winstate

import "testing"

func TestServiceJournalRetainsCompletedResourceIdentities(t *testing.T) {
	m, s, _, r := fixture(t)
	stored, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	stored.Routes = []RouteChange{{Route: r, State: "restored"}}
	if err = s.Save(stored); err != nil {
		t.Fatal(err)
	}
	j, err := m.load()
	if err != nil || len(j.Routes) != 0 {
		t.Fatal("legacy compaction changed", err)
	}
	m.RetainEvidence = true
	j, err = m.load()
	if err != nil || len(j.Routes) != 1 || j.Routes[0].State != "restored" {
		t.Fatal("service lost historical native identity", err)
	}
}
