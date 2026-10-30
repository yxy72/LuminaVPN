//go:build windows

package winproc

import (
	"errors"
	"golang.org/x/sys/windows"
	"netlaunch/internal/platform"
	"path/filepath"
	"testing"
	"time"
)

func fixtureCommand(t *testing.T) []string {
	t.Helper()
	dir, e := windows.GetSystemDirectory()
	if e != nil {
		t.Fatal(e)
	}
	return []string{filepath.Join(dir, "cmd.exe"), "/d", "/c", "exit", "17"}
}

func TestChildWaitsForPublication(t *testing.T) {
	j, e := NewJob()
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	called := false
	p, e := j.Start(Spec{Args: fixtureCommand(t)}, func(id platform.Identity) error {
		called = true
		// The owned command exits immediately when run; it must still be alive
		// while the publication callback holds its primary thread suspended.
		time.Sleep(100 * time.Millisecond)
		actual, e := platform.Process(id.PID)
		if e != nil {
			return e
		}
		if actual != id {
			return errors.New("child ran before publication")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	code, e := p.Wait()
	if e != nil || code != 17 || !called {
		t.Fatal("child result", code, e)
	}
}

func TestFailedPublicationKillsOnlySuspendedChild(t *testing.T) {
	j, e := NewJob()
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	var child platform.Identity
	failure := errors.New("simulated journal failure")
	p, e := j.Start(Spec{Args: fixtureCommand(t)}, func(id platform.Identity) error { child = id; return failure })
	if p != nil || !errors.Is(e, failure) {
		t.Fatal("failure not propagated", e)
	}
	current, e := platform.Process(child.PID)
	if e != nil {
		t.Fatal(e)
	}
	if current.PID != 0 && current.Birth == child.Birth {
		t.Fatal("unpublished child survived")
	}
}

func TestEnvironmentBlockIsBoundedAndCaseInsensitive(t *testing.T) {
	b, e := environmentBlock([]string{"Path=old", "PATH=new", "OPENSSL_CONF=NUL"})
	if e != nil {
		t.Fatal(e)
	}
	var all []string
	for len(b) > 1 {
		n := 0
		for b[n] != 0 {
			n++
		}
		all = append(all, windows.UTF16ToString(b[:n]))
		b = b[n+1:]
	}
	if len(all) != 2 || all[0] != "OPENSSL_CONF=NUL" || all[1] != "PATH=new" {
		t.Fatal("environment normalization", all)
	}
	if _, e = environmentBlock([]string{"BAD\x00KEY=1"}); e == nil {
		t.Fatal("NUL environment accepted")
	}
}

func TestIndependentChildPublishedBeforeResume(t *testing.T) {
	called := false
	p, e := StartIndependent(Spec{Args: fixtureCommand(t)}, func(id platform.Identity) error {
		called = true
		current, e := platform.Process(id.PID)
		if e != nil {
			return e
		}
		if current != id {
			return errors.New("independent child ran before publication")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	code, e := p.Wait()
	if e != nil || code != 17 || !called {
		t.Fatal("independent child", code, e)
	}
}
