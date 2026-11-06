//go:build windows

package engine

import (
	"errors"
	"testing"
	"time"

	"netlaunch/internal/platform"
)

func TestRecoveryHostExitRejectsUnknownConflictAndLiveOwner(t *testing.T) {
	expected := platform.Identity{PID: 51, Birth: "original-birth", OwnerSID: "S-1-5-18", Executable: `C:\Program Files\LuminaVPN\releases\fixture\lumina-service.exe`}
	for _, tc := range []struct {
		name   string
		actual platform.Identity
		err    error
	}{
		{"still_live", expected, nil},
		{"access_denied", platform.Identity{}, errors.New("access denied")},
		{"partial_absence", platform.Identity{Birth: "original-birth"}, nil},
		{"missing_birth", platform.Identity{PID: 51, OwnerSID: "S-1-5-18", Executable: expected.Executable}, nil},
		{"wrong_pid", platform.Identity{PID: 52, Birth: "another-birth", OwnerSID: "S-1-5-18", Executable: expected.Executable}, nil},
		{"same_birth_conflicting_image", platform.Identity{PID: 51, Birth: expected.Birth, OwnerSID: "S-1-5-18", Executable: `C:\other.exe`}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := time.Unix(1700000000, 0)
			calls := 0
			err := waitServiceHostExitedWith(expected, func(int) (platform.Identity, error) { calls++; return tc.actual, tc.err }, func() time.Time { return clock }, func(d time.Duration) { clock = clock.Add(d) })
			if err == nil || calls > 100 {
				t.Fatal("unknown/live owner became exited", err, calls)
			}
		})
	}
}

func TestRecoveryHostExitAcceptsExactAbsenceReuseAndBoundedDelayedExit(t *testing.T) {
	expected := platform.Identity{PID: 51, Birth: "original-birth", OwnerSID: "S-1-5-18", Executable: `C:\Program Files\LuminaVPN\releases\fixture\lumina-service.exe`}
	for _, reuse := range []bool{false, true} {
		clock := time.Unix(1700000000, 0)
		calls := 0
		err := waitServiceHostExitedWith(expected, func(pid int) (platform.Identity, error) {
			calls++
			if pid != expected.PID {
				t.Fatal("foreign PID query")
			}
			if calls < 3 {
				return expected, nil
			}
			if reuse {
				return platform.Identity{PID: pid, Birth: "new-birth", OwnerSID: "S-1-5-21-9", Executable: `C:\unrelated.exe`}, nil
			}
			return platform.Identity{}, nil
		}, func() time.Time { return clock }, func(d time.Duration) { clock = clock.Add(d) })
		if err != nil || calls != 3 {
			t.Fatal("bounded confirmed exit rejected", err, calls)
		}
	}
}

func TestRecoveryHostExitRejectsLateAbsenceMissingFrozenFieldsAndClockStall(t *testing.T) {
	expected := platform.Identity{PID: 51, Birth: "original-birth", OwnerSID: "S-1-5-18", Executable: `C:\Program Files\LuminaVPN\releases\fixture\lumina-service.exe`}
	clock := time.Unix(1700000000, 0)
	if err := waitServiceHostExitedWith(expected, func(int) (platform.Identity, error) {
		clock = clock.Add(5 * time.Second)
		return platform.Identity{}, nil
	}, func() time.Time { return clock }, func(time.Duration) {}); err == nil {
		t.Fatal("late absence accepted")
	}
	for _, edit := range []func(*platform.Identity){func(i *platform.Identity) { i.PID = 0 }, func(i *platform.Identity) { i.Birth = "" }, func(i *platform.Identity) { i.OwnerSID = "" }, func(i *platform.Identity) { i.Executable = "relative.exe" }} {
		bad := expected
		edit(&bad)
		if err := waitServiceHostExitedWith(bad, func(int) (platform.Identity, error) {
			t.Fatal("invalid frozen owner reached query")
			return platform.Identity{}, nil
		}, time.Now, func(time.Duration) {}); err == nil {
			t.Fatal("missing frozen owner accepted")
		}
	}
	calls := 0
	if err := waitServiceHostExitedWith(expected, func(int) (platform.Identity, error) { calls++; return expected, nil }, func() time.Time { return clock }, func(time.Duration) {}); err == nil || calls != 100 {
		t.Fatal("stalled clock was unbounded", calls)
	}
	if err := VerifyServiceHostExited(expected, ""); err == nil {
		t.Fatal("missing frozen pin accepted")
	}
}
