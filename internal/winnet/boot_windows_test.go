//go:build windows

package winnet

import "testing"

func TestBootIdentityReadOnly(t *testing.T) {
	a, e := BootID()
	if e != nil {
		t.Fatal(e)
	}
	b, e := BootID()
	if e != nil || a == "" || a != b {
		t.Fatal("unstable native boot identity", e)
	}
}
