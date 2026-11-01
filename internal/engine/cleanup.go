package engine

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type CleanupResult struct {
	Scope            string `json:"scope"`
	Applied          bool   `json:"applied"`
	Files            int    `json:"files"`
	Bytes            int64  `json:"bytes"`
	RecoveryRetained bool   `json:"recovery_retained"`
}

// Cleanup removes bulky payloads only. Recovery evidence, frozen launchers,
// STOP, manifests and lock files are intentionally never cleanup candidates.
func cleanupPayload(name string) bool {
	return name == "runtime" || name == "auth.json" || name == "auth-refresh.json" || name == "nodes.json" || name == "core.json" || strings.HasSuffix(name, ".log")
}

type cleanupTree struct {
	root  *os.Root
	names []string
	files int
	bytes int64
}

func planCleanupTree(path string) (*cleanupTree, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("cleanup root is not a regular directory")
	}
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			r.Close()
		}
	}()
	after, err := r.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("cleanup root changed")
	}
	t := &cleanupTree{root: r}
	err = fs.WalkDir(r.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		top := strings.SplitN(name, "/", 2)[0]
		if !cleanupPayload(top) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return errors.New("cleanup payload contains a link or special file")
		}
		if name == top {
			if info.IsDir() && name != "runtime" {
				return errors.New("unexpected payload directory")
			}
			t.names = append(t.names, name)
		}
		if !info.IsDir() {
			t.files++
			t.bytes += info.Size()
		}
		if t.files > 100000 {
			return errors.New("cleanup payload too large to enumerate")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	ok = true
	return t, nil
}

func (t *cleanupTree) apply() error {
	for _, name := range t.names {
		// Root.RemoveAll never follows links or escapes the pinned run root,
		// including when an owner edits the public payload after preview.
		if err := t.root.RemoveAll(name); err != nil {
			return err
		}
	}
	return nil
}

func cleanupLocation(profile, run string) error {
	if !filepath.IsAbs(profile) || filepath.Clean(profile) != profile || filepath.Dir(run) != filepath.Join(profile, "runs") {
		return errors.New("cleanup requires a direct child of the profile runs directory")
	}
	resolved, err := filepath.EvalSymlinks(run)
	if err != nil || resolved != run {
		return errors.New("cleanup path contains a link or alias")
	}
	return ValidateRun(run)
}
