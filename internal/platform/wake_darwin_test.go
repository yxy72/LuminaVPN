//go:build darwin

package platform

import "testing"

func TestNativeWakeEpochReadOnly(t *testing.T) {
	a, e := WakeEpoch()
	if e != nil {
		t.Fatal(e)
	}
	b, e := WakeEpoch()
	if e != nil || a == "" || a != b {
		t.Fatal("unstable boot/wake identity", e)
	}
}
