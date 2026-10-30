//go:build windows

package winnet

import "testing"

func TestPowerEpochRegistrationAndRevocation(t *testing.T) {
	p, e := WatchPower()
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	before, awake := p.Epoch()
	if !awake || before == 0 {
		t.Fatal("initial power generation")
	}
	// Exercise only our callback state transition; the computer does not sleep.
	advancePower(p, 4)
	suspend, awake := p.Epoch()
	if awake || suspend == before {
		t.Fatal("suspend failed to revoke")
	}
	advancePower(p, 18)
	resume, awake := p.Epoch()
	if !awake || resume == suspend {
		t.Fatal("resume reused generation")
	}
	advancePower(p, 99)
	after, _ := p.Epoch()
	if after != resume {
		t.Fatal("unrelated event changed epoch")
	}
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
	if _, ok := powerWatches.Load(p.id); ok {
		t.Fatal("unregistered callback retained")
	}
}
