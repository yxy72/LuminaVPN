//go:build windows

package main

import (
	"errors"
	"netlaunch/internal/platform"
	"testing"
	"time"
)

func TestOwnerQueryFailureKeepsDeadlineArmed(t *testing.T) {
	deadline, ticks := make(chan time.Time), make(chan time.Time)
	reported, done := make(chan struct{}, 1), make(chan error, 1)
	var reason string
	go func() {
		done <- monitorProbeOwner(platform.Identity{PID: 42}, deadline, ticks, func() bool { return false }, func(int) (platform.Identity, error) { return platform.Identity{}, errors.New("access denied") }, func(s string) error { reason = s; return nil }, func(error) { reported <- struct{}{} })
	}()
	ticks <- time.Now()
	<-reported
	select {
	case <-done:
		t.Fatal("query failure disarmed watchdog")
	default:
	}
	deadline <- time.Now()
	if err := <-done; err != nil || reason != "deadline" {
		t.Fatal(reason, err)
	}
}

func TestOwnerQueryCanRecoverAfterTransientFailure(t *testing.T) {
	deadline, ticks := make(chan time.Time), make(chan time.Time)
	reported, done := make(chan struct{}, 1), make(chan error, 1)
	queries, reason := 0, ""
	go func() {
		done <- monitorProbeOwner(platform.Identity{PID: 42, Birth: "old"}, deadline, ticks, func() bool { return false }, func(int) (platform.Identity, error) {
			queries++
			if queries == 1 {
				return platform.Identity{}, errors.New("temporary")
			}
			return platform.Identity{PID: 42, Birth: "reused"}, nil
		}, func(s string) error { reason = s; return nil }, func(error) { reported <- struct{}{} })
	}()
	ticks <- time.Now()
	<-reported
	ticks <- time.Now()
	if err := <-done; err != nil || reason != "owner_exited" {
		t.Fatal(reason, err)
	}
}
