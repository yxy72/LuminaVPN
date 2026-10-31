//go:build windows

package winproc

import (
	"errors"
	"golang.org/x/sys/windows"
	"netlaunch/internal/platform"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"
)

func TestIndependentNestedChild(t *testing.T) {
	if os.Getenv("NETLAUNCH_TEST_NESTED_CHILD") == "1" {
		var inside uint32
		ok, _, err := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob").Call(uintptr(windows.CurrentProcess()), 0, uintptr(unsafe.Pointer(&inside)))
		var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		var size uint32
		query := windows.QueryInformationJobObject(0, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)), &size)
		t.Logf("native job query ok=%d in_job=%d error=%v limits_error=%v flags=%x", ok, inside, err, query, limits.BasicLimitInformation.LimitFlags)
		published := false
		p, e := StartIndependent(Spec{Args: fixtureCommand(t)}, func(platform.Identity) error { published = true; return nil })
		// Some hosts place a detached process in another non-breakaway job.
		// In that case the API must fail closed before publishing/running a
		// child; it must never silently retry without independent lifetime.
		if ok != 0 && inside != 0 && query == nil && limits.BasicLimitInformation.LimitFlags&(windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK|windows.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) == 0 {
			if !errors.Is(e, windows.ERROR_ACCESS_DENIED) || p != nil || published {
				t.Fatal("non-breakaway job did not fail closed", e)
			}
			return
		}
		if e != nil {
			t.Fatal(e)
		}
		code, e := p.Wait()
		if e != nil || code != 17 {
			t.Fatal(code, e)
		}
		return
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	out, e := os.Create(filepath.Join(t.TempDir(), "nested.log"))
	if e != nil {
		t.Fatal(e)
	}
	defer out.Close()
	in, e := os.Open(os.DevNull)
	if e != nil {
		t.Fatal(e)
	}
	defer in.Close()
	p, e := StartIndependent(Spec{Args: []string{exe, "-test.run=^TestIndependentNestedChild$", "-test.v"}, Environment: append(os.Environ(), "NETLAUNCH_TEST_NESTED_CHILD=1"), Stdin: in, Stdout: out, Stderr: out}, func(platform.Identity) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	code, e := p.Wait()
	if e != nil || code != 0 {
		b, _ := os.ReadFile(out.Name())
		t.Fatalf("nested independent launch: %d %v %s", code, e, b)
	}
}

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
