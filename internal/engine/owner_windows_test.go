//go:build windows

package engine

import (
	"netlaunch/internal/testutil"
	"testing"
)

func TestWindowsManifestRequiresSameUser(t *testing.T) {
	run := testutil.PrivateTempDir(t)
	uid, sid, e := OwnerIdentity()
	if e != nil || uid != 0 || sid == "" {
		t.Fatal("native user identity", e)
	}
	m := Manifest{Owner: uid, OwnerSID: sid}
	if e = validateOwner(run, m); e != nil {
		t.Fatal("same-user run rejected", e)
	}
	m.OwnerSID = "S-1-5-18"
	if e = validateOwner(run, m); e == nil {
		t.Fatal("different UAC user accepted")
	}
	m.OwnerSID = sid
	m.Owner = 501
	if e = validateOwner(run, m); e == nil {
		t.Fatal("Unix owner accepted on Windows")
	}
}
