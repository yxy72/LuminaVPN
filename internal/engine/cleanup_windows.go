//go:build windows

package engine

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/winstate"
)

func sameCleanupPath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func cleanupGlobalLock(run string) (func(), error) {
	files, _, err := winFiles(run)
	if err != nil {
		return nil, err
	}
	unlock, err := files.Lock("active.lock", time.Second)
	if err != nil {
		return nil, err
	}
	b, err := files.Read("active.json", 4096)
	if errors.Is(err, os.ErrNotExist) {
		return unlock, nil
	}
	if err == nil {
		var ref struct {
			Run string `json:"run"`
		}
		if json.Unmarshal(b, &ref) != nil || ref.Run == "" {
			err = errors.New("invalid administrator run reference")
		} else if sameCleanupPath(ref.Run, run) {
			err = errors.New("administrator current run is retained")
		}
	}
	if err != nil {
		unlock()
		return nil, err
	}
	return unlock, nil
}

func cleanupProcessGone(pid int) error {
	if pid == 0 {
		return nil
	}
	id, err := platform.Process(pid)
	if err != nil {
		return err
	}
	if id.PID != 0 {
		return errors.New("recorded process id is still in use; cleanup refused")
	}
	return nil
}

func cleanupRecovered(run string, s State) error {
	var j winstate.Journal
	if err := winRead(run, "network.json", &j); err != nil {
		return err
	}
	if s.Windows == nil || j.BootID != s.Windows.BootID {
		return errors.New("recovery journal identity differs")
	}
	return winstate.CheckRecovered(j)
}
