//go:build darwin || windows

package engine

import (
	"errors"
	"os"
)

func initializeStateStorage(run string, s *State) error {
	if _, err := readRunFile(run, "run-spec.json", 2<<20); !errors.Is(err, os.ErrNotExist) {
		return errors.New("run specification already exists or cannot be inspected")
	}
	spec := immutableRunSpec(s.Manifest)
	if err := writeRunFile(run, "run-spec.json", spec); err != nil {
		return err
	}
	s.Version, s.RunSpecDigest = currentStateVersion, runSpecDigest(spec)
	return nil
}
