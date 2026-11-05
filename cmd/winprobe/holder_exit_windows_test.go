//go:build windows

package main

import (
	"errors"
	"netlaunch/internal/platform"
	"testing"
	"time"
)

type holderExitClock struct {
	start time.Time
	nowAt time.Time
}

func newHolderExitClock() *holderExitClock {
	start := time.Date(2026, time.November, 5, 10, 0, 0, 0, time.UTC)
	return &holderExitClock{start: start, nowAt: start}
}

func (c *holderExitClock) now() time.Time { return c.nowAt }
func (c *holderExitClock) sleep(d time.Duration) {
	c.nowAt = c.nowAt.Add(d)
}
func (c *holderExitClock) elapsed() time.Duration { return c.nowAt.Sub(c.start) }

func probeHolderFixtureIdentity() platform.Identity {
	return platform.Identity{PID: 4242, Birth: "fixture-generation", Executable: `C:\fixture\winprobe.exe`, Command: "holder", OwnerSID: "S-1-5-21-fixture"}
}

func TestProbeHolderForcedExitIsNotCleanRecovery(t *testing.T) {
	clock := newHolderExitClock()
	expected := probeHolderFixtureIdentity()
	stopCalls, reports := 0, 0
	stopped, err := waitProbeHolderExit(expected, func(pid int) (platform.Identity, error) {
		if pid != expected.PID {
			t.Fatalf("queried an unowned PID: %d", pid)
		}
		if stopCalls != 0 {
			return platform.Identity{}, nil
		}
		return expected, nil
	}, func(actual platform.Identity) error {
		stopCalls++
		if actual != expected || clock.elapsed() != 15*time.Second || reports != 1 {
			t.Fatalf("termination did not use the published identity after timeout report: %#v, elapsed=%v reports=%d", actual, clock.elapsed(), reports)
		}
		return nil
	}, clock.now, clock.sleep, func() error { reports++; return nil })
	if !stopped || !errors.Is(err, errProbeHolderCloseTimeout) || stopCalls != 1 || reports != 1 {
		t.Fatalf("forced exit became a clean pass: stopped=%v err=%v stops=%d reports=%d", stopped, err, stopCalls, reports)
	}
}

func TestProbeHolderIdentityChangeNeverTerminatesReplacement(t *testing.T) {
	expected := probeHolderFixtureIdentity()
	for name, change := range map[string]func(*platform.Identity){
		"gone":       func(id *platform.Identity) { *id = platform.Identity{} },
		"birth":      func(id *platform.Identity) { id.Birth = "replacement-generation" },
		"executable": func(id *platform.Identity) { id.Executable = `C:\foreign.exe` },
		"command":    func(id *platform.Identity) { id.Command = "foreign" },
		"owner":      func(id *platform.Identity) { id.OwnerSID = "S-1-5-21-other" },
	} {
		t.Run(name, func(t *testing.T) {
			clock := newHolderExitClock()
			replacement := expected
			change(&replacement)
			stopped, err := waitProbeHolderExit(expected, func(int) (platform.Identity, error) {
				if clock.elapsed() >= 3*time.Second {
					return replacement, nil
				}
				return expected, nil
			}, func(platform.Identity) error { t.Fatal("terminated a replacement process"); return nil }, clock.now, clock.sleep, func() error { t.Fatal("reported a timeout after original identity exited"); return nil })
			if !stopped || err != nil || clock.elapsed() != 3*time.Second {
				t.Fatalf("original holder disappearance was not recognized: stopped=%v err=%v elapsed=%v", stopped, err, clock.elapsed())
			}
		})
	}
}

func TestProbeHolderQueryErrorIsNotProcessExit(t *testing.T) {
	for _, afterStop := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal_wait", true: "forced_wait"}[afterStop], func(t *testing.T) {
			clock := newHolderExitClock()
			expected := probeHolderFixtureIdentity()
			queryErr := errors.New("identity API unavailable")
			stopCalls := 0
			stopped, err := waitProbeHolderExit(expected, func(int) (platform.Identity, error) {
				if !afterStop || stopCalls != 0 {
					return platform.Identity{}, queryErr
				}
				return expected, nil
			}, func(actual platform.Identity) error { stopCalls++; return nil }, clock.now, clock.sleep, nil)
			if stopped || !errors.Is(err, queryErr) {
				t.Fatalf("API error was accepted as holder exit: stopped=%v err=%v", stopped, err)
			}
			if afterStop && (stopCalls != 1 || !errors.Is(err, errProbeHolderCloseTimeout)) {
				t.Fatalf("forced wait lost timeout evidence: stops=%d err=%v", stopCalls, err)
			}
			if !afterStop && (stopCalls != 0 || clock.elapsed() != 0) {
				t.Fatalf("API error did not fail immediately: stops=%d elapsed=%v", stopCalls, clock.elapsed())
			}
		})
	}
}

func TestProbeHolderNeverExitsHasTwentySecondBound(t *testing.T) {
	clock := newHolderExitClock()
	expected := probeHolderFixtureIdentity()
	stopCalls := 0
	stopped, err := waitProbeHolderExit(expected, func(int) (platform.Identity, error) { return expected, nil }, func(actual platform.Identity) error {
		stopCalls++
		if actual != expected {
			t.Fatalf("terminated an unowned identity: %#v", actual)
		}
		return nil
	}, clock.now, clock.sleep, nil)
	if stopped || !errors.Is(err, errProbeHolderCloseTimeout) || stopCalls != 1 || clock.elapsed() != 20*time.Second {
		t.Fatalf("unbounded or successful stuck-holder recovery: stopped=%v err=%v stops=%d elapsed=%v", stopped, err, stopCalls, clock.elapsed())
	}
}

func TestProbeHolderReportErrorStillTerminatesExactIdentity(t *testing.T) {
	clock := newHolderExitClock()
	expected := probeHolderFixtureIdentity()
	reportErr := errors.New("timeout audit write failed")
	stopCalls := 0
	stopped, err := waitProbeHolderExit(expected, func(int) (platform.Identity, error) {
		if stopCalls != 0 {
			return platform.Identity{}, nil
		}
		return expected, nil
	}, func(actual platform.Identity) error {
		stopCalls++
		if actual != expected {
			t.Fatalf("terminated an unowned identity: %#v", actual)
		}
		return nil
	}, clock.now, clock.sleep, func() error { return reportErr })
	if !stopped || stopCalls != 1 || !errors.Is(err, reportErr) || !errors.Is(err, errProbeHolderCloseTimeout) {
		t.Fatalf("audit failure skipped termination or was discarded: stopped=%v err=%v stops=%d", stopped, err, stopCalls)
	}
}

func TestProbeHolderTerminationErrorIsNotProcessExit(t *testing.T) {
	clock := newHolderExitClock()
	expected := probeHolderFixtureIdentity()
	stopErr := errors.New("exact identity termination denied")
	stopped, err := waitProbeHolderExit(expected, func(int) (platform.Identity, error) { return expected, nil }, func(actual platform.Identity) error { return stopErr }, clock.now, clock.sleep, nil)
	if stopped || !errors.Is(err, stopErr) || !errors.Is(err, errProbeHolderCloseTimeout) || clock.elapsed() != 15*time.Second {
		t.Fatalf("termination failure became process exit: stopped=%v err=%v elapsed=%v", stopped, err, clock.elapsed())
	}
}

func TestProbeHolderLateNaturalExitRetainsTimeoutAndStopsExactIdentity(t *testing.T) {
	clock := newHolderExitClock()
	expected := probeHolderFixtureIdentity()
	stopCalls, reports := 0, 0
	stopped, err := waitProbeHolderExit(expected, func(pid int) (platform.Identity, error) {
		if pid != expected.PID {
			t.Fatalf("queried an unowned PID: %d", pid)
		}
		if stopCalls == 0 {
			// The query began in time, but its exit result arrived too late.
			clock.sleep(16 * time.Second)
		}
		return platform.Identity{}, nil
	}, func(actual platform.Identity) error {
		stopCalls++
		if actual != expected || reports != 1 {
			t.Fatalf("late query skipped reporting or changed termination authority: identity=%#v reports=%d", actual, reports)
		}
		return nil
	}, clock.now, clock.sleep, func() error { reports++; return nil })
	if !stopped || !errors.Is(err, errProbeHolderCloseTimeout) || stopCalls != 1 || reports != 1 || clock.elapsed() != 16*time.Second {
		t.Fatalf("late natural exit became a clean recovery: stopped=%v err=%v stops=%d reports=%d elapsed=%v", stopped, err, stopCalls, reports, clock.elapsed())
	}
}

func TestProbeHolderLateForcedExitDoesNotConfirmWithinBound(t *testing.T) {
	clock := newHolderExitClock()
	expected := probeHolderFixtureIdentity()
	stopCalls := 0
	stopped, err := waitProbeHolderExit(expected, func(int) (platform.Identity, error) {
		if stopCalls != 0 {
			// Exit is reported, but only after the forced-wait deadline.
			clock.sleep(6 * time.Second)
			return platform.Identity{}, nil
		}
		return expected, nil
	}, func(actual platform.Identity) error {
		stopCalls++
		if actual != expected {
			t.Fatalf("terminated an unowned identity: %#v", actual)
		}
		return nil
	}, clock.now, clock.sleep, nil)
	if stopped || !errors.Is(err, errProbeHolderCloseTimeout) || stopCalls != 1 || clock.elapsed() != 21*time.Second {
		t.Fatalf("late forced exit counted as confirmed within bound: stopped=%v err=%v stops=%d elapsed=%v", stopped, err, stopCalls, clock.elapsed())
	}
}
