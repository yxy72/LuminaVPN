package winstate

import "testing"

func TestCleanupRequiresEveryJournalResourceRestored(t *testing.T) {
	base := Journal{Version: 1, BootID: "fixture", Stopping: true}
	if err := CheckRecovered(base); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*Journal){
		func(j *Journal) { j.Stopping = false },
		func(j *Journal) { j.Routes = []RouteChange{{State: "applied"}} },
		func(j *Journal) { j.DNS = []DNSChange{{State: "restoring"}} },
		func(j *Journal) { j.Addresses = []AddressChange{{State: "planned"}} },
		func(j *Journal) { j.MTU = []MTUChange{{State: "unknown"}} },
		func(j *Journal) { j.Guards = []GuardChange{{State: "applied"}} },
		func(j *Journal) {
			j.Pairs = []PairChange{{VPN: RouteChange{State: "restored"}, Capture: RouteChange{State: "applied"}}}
		},
	} {
		j := base
		edit(&j)
		if err := CheckRecovered(j); err == nil {
			t.Fatal("accepted incomplete recovery", j)
		}
	}
	base.Routes = []RouteChange{{State: "restored"}}
	base.DNS = []DNSChange{{State: "restored"}}
	base.Addresses = []AddressChange{{State: "restored"}}
	base.MTU = []MTUChange{{State: "restored"}}
	base.Guards = []GuardChange{{State: "restored"}}
	base.Pairs = []PairChange{{VPN: RouteChange{State: "restored"}, Capture: RouteChange{State: "restored"}}}
	if err := CheckRecovered(base); err != nil {
		t.Fatal(err)
	}
}
