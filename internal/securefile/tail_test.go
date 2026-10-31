package securefile_test

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"testing"

	"netlaunch/internal/securefile"
	"netlaunch/internal/testutil"
)

func TestPrivateReadTailIsBoundedAndStillChecksPermissions(t *testing.T) {
	root := testutil.PrivateTempDir(t)
	path := filepath.Join(root, "long.log")
	data := append(bytes.Repeat([]byte("fixture\n"), 50000), []byte("authentication failed\n")...)
	if err := securefile.Bytes(path, data); err != nil {
		t.Fatal(err)
	}
	got, err := securefile.ReadTail(path, 64, true)
	if err != nil || !bytes.Equal(got, data[len(data)-64:]) {
		t.Fatal("tail mismatch", err)
	}
	if _, err := securefile.Read(path, 64, true); err == nil {
		t.Fatal("ordinary bounded read weakened")
	}
	for _, limit := range []int64{-1, math.MaxInt64} {
		if _, err := securefile.ReadTail(path, limit, true); err == nil {
			t.Fatal("invalid limit accepted")
		}
	}
	if _, err := securefile.ReadTail(root, 64, true); err == nil {
		t.Fatal("directory accepted")
	}
	if err := securefile.Bytes(path, []byte("short")); err != nil {
		t.Fatal(err)
	}
	got, err = securefile.ReadTail(path, 64, true)
	if err != nil || string(got) != "short" {
		t.Fatal("short tail mismatch", err)
	}
	link := filepath.Join(root, "linked.log")
	if err := os.Symlink(path, link); err == nil {
		if _, err := securefile.ReadTail(link, 64, true); err == nil {
			t.Fatal("symlink accepted")
		}
	}
	testutil.MakePublic(t, path)
	if _, err := securefile.ReadTail(path, 64, true); err == nil {
		t.Fatal("public private-log accepted")
	}
}
