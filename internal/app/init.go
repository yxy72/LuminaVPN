package app

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"netlaunch/internal/securefile"
	"netlaunch/internal/subscription"
)

// Serialize initialization and undo only files created by this invocation.
func initializeProfile(profile string, data []byte, sources *subscription.Sources) error {
	if e := securefile.Dir(profile); e != nil {
		return e
	}
	unlock, e := securefile.Lock(filepath.Join(profile, "init.lock"), time.Second)
	if e != nil {
		return e
	}
	defer unlock()
	for _, name := range []string{"policy.json", "sources.json", "nodes.json", "subscription-cache.json"} {
		if _, e := os.Lstat(filepath.Join(profile, name)); !errors.Is(e, os.ErrNotExist) {
			return errors.New("profile already contains configuration; existing files were not overwritten")
		}
	}
	if sources != nil {
		if e := securefile.Write(filepath.Join(profile, "sources.json"), sources); e != nil {
			return e
		}
	}
	if e := securefile.Bytes(filepath.Join(profile, "policy.json"), data); e != nil {
		if sources != nil {
			_ = os.Remove(filepath.Join(profile, "sources.json"))
		}
		return e
	}
	return nil
}
