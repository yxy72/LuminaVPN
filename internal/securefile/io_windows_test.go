//go:build windows

package securefile

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestAtomicRenameVariablePathLengths(t *testing.T) {
	dir := filepath.Join(tree(t), "rename")
	if e := Dir(dir); e != nil {
		t.Fatal(e)
	}
	for n := 1; n <= 32; n++ {
		path := filepath.Join(dir, strings.Repeat("x", n)+"-缓存.json")
		for _, want := range []string{"initial", "replacement"} {
			if e := Bytes(path, []byte(want)); e != nil {
				t.Fatalf("length %d: %v", n, e)
			}
			got, e := Read(path, 128, true)
			if e != nil || string(got) != want {
				t.Fatalf("length %d: expected exact target contents; read error: %v", n, e)
			}
		}
	}
	rows, e := os.ReadDir(dir)
	if e != nil || len(rows) != 32 {
		t.Fatalf("unexpected rename artifacts: count=%d error=%v", len(rows), e)
	}
}

func TestIOPrivateRoundTrip(t *testing.T) {
	dir := filepath.Join(tree(t), "io")
	if e := Dir(dir); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dir, "session.json")
	if e := Write(p, map[string]string{"cookie": "fixture-only"}); e != nil {
		t.Fatal(e)
	}
	b, e := Read(p, 1024, true)
	if e != nil || !bytes.Contains(b, []byte("fixture-only")) {
		t.Fatal("round trip", e)
	}
	if _, e := Read(p, int64(len(b)-1), true); e == nil {
		t.Fatal("read limit ignored")
	}
	if _, e := Read(p, -1, true); e == nil {
		t.Fatal("negative read limit")
	}
	if _, e := Read(p, math.MaxInt64, true); e == nil {
		t.Fatal("overflowing read limit")
	}
	if _, e := Read(dir, 1024, true); e == nil {
		t.Fatal("directory read accepted")
	}
	if e := Bytes(p, []byte("replacement")); e != nil {
		t.Fatal(e)
	}
	b, e = Read(p, 11, true)
	if e != nil || string(b) != "replacement" {
		t.Fatal("replacement", e)
	}
	tmp, e := TempDir(dir, "netlaunch-")
	if e != nil {
		t.Fatal(e)
	}
	if e := CheckDir(tmp); e != nil {
		t.Fatal(e)
	}
	if _, e := TempDir(dir, `..\escape`); e == nil {
		t.Fatal("unsafe prefix accepted")
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 2 {
		t.Fatal("temporary file leak", e, len(entries))
	}
}

func TestIORejectUnsafeWithoutRepair(t *testing.T) {
	dir := filepath.Join(tree(t), "io")
	if e := Dir(dir); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dir, "public")
	if e := os.WriteFile(p, []byte("original"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Read(p, 1024, true); e == nil {
		t.Fatal("inherited file accepted")
	}
	if e := Bytes(p, []byte("replacement")); e == nil {
		t.Fatal("unsafe file replaced")
	}
	b, e := Read(p, 1024, false)
	if e != nil || string(b) != "original" {
		t.Fatal("external file import", e)
	}
	if e := ProtectFile(p); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, "link")
	if e := os.Link(p, link); e != nil {
		t.Fatal(e)
	}
	if _, e := Read(p, 1024, true); e == nil {
		t.Fatal("hardlink read accepted")
	}
	if e := Bytes(p, nil); e == nil {
		t.Fatal("hardlink replaced")
	}
	if e := os.Remove(link); e != nil {
		t.Fatal(e)
	}
	user, e := currentSID()
	if e != nil {
		t.Fatal(e)
	}
	setTestSD(t, dir, "D:P(A;OICI;FA;;;"+user+")(A;OICI;GR;;;WD)")
	if _, e := Read(p, 1024, true); e == nil {
		t.Fatal("unsafe parent read")
	}
	if e := Bytes(p, nil); e == nil {
		t.Fatal("unsafe parent write")
	}
	b, e = os.ReadFile(p)
	if e != nil || string(b) != "original" {
		t.Fatal("rejected operation altered data", e)
	}
}

func TestIOAtomicReaders(t *testing.T) {
	dir := filepath.Join(tree(t), "io")
	if e := Dir(dir); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dir, "state")
	a, b := bytes.Repeat([]byte("a"), 65536), bytes.Repeat([]byte("b"), 65536)
	if e := Bytes(p, a); e != nil {
		t.Fatal(e)
	}
	errs := make(chan error, 4)
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 80; j++ {
				v, e := Read(p, int64(len(a)), true)
				if e != nil {
					errs <- e
					return
				}
				if !bytes.Equal(v, a) && !bytes.Equal(v, b) {
					errs <- fmt.Errorf("torn snapshot: %d bytes", len(v))
					return
				}
			}
		}()
	}
	for i := 0; i < 40; i++ {
		v := a
		if i%2 == 0 {
			v = b
		}
		if e := Bytes(p, v); e != nil {
			t.Error(e)
			break
		}
	}
	readers.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
