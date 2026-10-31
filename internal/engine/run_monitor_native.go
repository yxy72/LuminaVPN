//go:build darwin || windows

package engine

import (
	"errors"
	"os"
	"time"
)

func readMonitor(run string, s State) (runMonitor, error) {
	if s.Version == 1 {
		return baselineMonitor(s), nil
	}
	raw, err := readRunFile(run, "heartbeat.json", 16<<10)
	if errors.Is(err, os.ErrNotExist) {
		return baselineMonitor(s), nil
	}
	if err != nil {
		return runMonitor{}, err
	}
	return decodeMonitor(raw, s)
}

func pulse(run string) error      { return writePulse(run, true) }
func alivePulse(run string) error { return writePulse(run, false) }

func writePulse(run string, progress bool) error {
	unlock, err := lockRunFile(run, "heartbeat.lock", 2*time.Second)
	if err != nil {
		return err
	}
	defer unlock()
	s, err := load(run)
	if err != nil {
		return err
	}
	if s.Version == 1 {
		return legacyPulse(run)
	}
	if err := guard(run, &s); err != nil {
		return err
	}
	if err := verifyPulseProcesses(s); err != nil {
		return err
	}
	m, err := readMonitor(run, s)
	if err != nil {
		return err
	}
	m, err = advanceMonitor(s, m, time.Now(), progress)
	if err != nil {
		return err
	}
	return writeRunFile(run, "heartbeat.json", m)
}
