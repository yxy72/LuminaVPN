//go:build windows

package main

import (
	"errors"
	"os"
)

var errAutomaticRecoveryPreviouslyFailed = errors.New("a previous recovery attempt failed; automatic close cannot pass bounded validation")

func automaticRecoveryQualification(previous map[string]any, currentErr error) error {
	if _, failed := previous["first_failure"]; failed {
		return errors.Join(currentErr, errAutomaticRecoveryPreviouslyFailed)
	}
	return currentErr
}

// lock is distinct from the resource recovery lock and held only for this
// first-publication transaction. Concurrent watchers cannot replace the first
// terminal outcome, even if another watcher subsequently finishes cleanup.
func publishFirstAutomaticResult(lock func() (func(), error), load func() (map[string]any, error), write func(map[string]any) error, candidate map[string]any) (map[string]any, error) {
	unlock, err := lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	original, err := load()
	if err == nil {
		return original, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err = write(candidate); err != nil {
		return nil, err
	}
	return candidate, nil
}
