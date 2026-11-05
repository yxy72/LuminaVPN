//go:build windows

package main

import (
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestFirstAutomaticTerminalIsImmutableUnderConcurrentPublication(t *testing.T) {
	var mu sync.Mutex
	var stored map[string]any
	writes := 0
	lock := func() (func(), error) { mu.Lock(); return mu.Unlock, nil }
	load := func() (map[string]any, error) {
		if stored == nil {
			return nil, os.ErrNotExist
		}
		return stored, nil
	}
	write := func(m map[string]any) error { writes++; stored = m; return nil }
	first := mergeRecoveryResult(nil, "deadline", errProbeHolderCloseTimeout, time.Time{})
	// Hold the first writer inside its locked transaction while competitors
	// are launched, reproducing the old load-missing/replace-write race.
	entered, release := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := publishFirstAutomaticResult(lock, func() (map[string]any, error) { close(entered); <-release; return load() }, write, first)
		if err != nil {
			t.Error(err)
		}
	}()
	<-entered
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := publishFirstAutomaticResult(lock, load, write, map[string]any{"recovered": true})
			if err != nil || !reflect.DeepEqual(result, first) {
				t.Error("first failed terminal replaced", result, err)
			}
		}()
	}
	close(release)
	wg.Wait()
	if writes != 1 || !reflect.DeepEqual(stored, first) {
		t.Fatal(writes, stored)
	}
}

func TestAutomaticQualificationRetainsOtherWatchersFailure(t *testing.T) {
	history := mergeRecoveryResult(nil, "deadline", errProbeHolderCloseTimeout, time.Time{})
	history = mergeRecoveryResult(history, "manual", nil, time.Time{}.Add(time.Second))
	err := automaticRecoveryQualification(history, nil)
	if !errors.Is(err, errAutomaticRecoveryPreviouslyFailed) {
		t.Fatal("cleanup success erased failed attempt", err)
	}
}

func TestUnreadableFirstAutomaticTerminalIsNeverReplaced(t *testing.T) {
	bad := errors.New("first terminal unreadable")
	_, err := publishFirstAutomaticResult(func() (func(), error) { return func() {}, nil }, func() (map[string]any, error) { return nil, bad }, func(map[string]any) error { t.Fatal("must preserve original"); return nil }, map[string]any{"recovered": true})
	if !errors.Is(err, bad) {
		t.Fatal(err)
	}
}
