//go:build !windows

package securefile

import (
	"errors"
	"os"
)

func CheckDir(path string) error {
	i, e := os.Lstat(path)
	if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm()&0077 != 0 {
		return errors.New("directory must be private and not a symlink")
	}
	return nil
}
func TempDir(parent, prefix string) (string, error) {
	if e := Dir(parent); e != nil {
		return "", e
	}
	return os.MkdirTemp(parent, prefix)
}
