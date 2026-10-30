//go:build darwin

package engine

import (
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/testutil"
	"os"
	"path/filepath"
	"testing"
)

func TestManifestOwnershipMatchesRunDirectory(t *testing.T) {
	root := testutil.PrivateTempDir(t)
	run := filepath.Join(root, "netlaunch-owner-test")
	if e := securefile.Dir(run); e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile("../../examples/policy.json")
	if e != nil {
		t.Fatal(e)
	}
	config, e := policy.Decode(data)
	if e != nil {
		t.Fatal(e)
	}
	uid, sid, e := OwnerIdentity()
	if e != nil {
		t.Fatal(e)
	}
	m := Manifest{Version: 1, Owner: uid, OwnerSID: sid, Config: config}
	if e = securefile.Write(filepath.Join(run, "manifest.json"), m); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadManifest(run); e != nil {
		t.Fatal("valid current user rejected", e)
	}
	m.Owner++
	if e = securefile.Write(filepath.Join(run, "manifest.json"), m); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadManifest(run); e == nil {
		t.Fatal("foreign UID accepted")
	}
	m.Owner = uid
	m.OwnerSID = "S-1-5-21-test"
	if e = securefile.Write(filepath.Join(run, "manifest.json"), m); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadManifest(run); e == nil {
		t.Fatal("Windows owner accepted on Mac")
	}
}
