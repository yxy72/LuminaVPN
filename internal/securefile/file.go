//go:build !windows

package securefile

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
)

func Dir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	i, err := os.Lstat(path)
	if err != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm()&0077 != 0 {
		return errors.New("state directory must be private and not a symlink")
	}
	return nil
}

func Read(path string, limit int64, private bool) ([]byte, error) {
	return readBounded(path, limit, private, false)
}

// ReadTail reads at most limit bytes from the end of a verified regular file.
// It uses the same identity and permission checks as Read, without loading a
// potentially long-lived component log into memory.
func ReadTail(path string, limit int64, private bool) ([]byte, error) {
	return readBounded(path, limit, private, true)
}

func readBounded(path string, limit int64, private, tail bool) ([]byte, error) {
	if limit < 0 || limit == math.MaxInt64 {
		return nil, errors.New("invalid read limit")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || (!tail && before.Size() > limit) {
		return nil, errors.New("expected a bounded regular file, not a symlink")
	}
	if private && before.Mode().Perm()&0077 != 0 {
		return nil, errors.New("secret file must have mode 0600 or stricter")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("file identity changed while opening")
	}
	if tail {
		if after.Size() > limit {
			if _, err := f.Seek(after.Size()-limit, io.SeekStart); err != nil {
				return nil, err
			}
		}
		return io.ReadAll(io.LimitReader(f, limit))
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if len(b) > int(limit) {
		return nil, errors.New("file size limit exceeded")
	}
	return b, err
}

func Write(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return Bytes(path, append(b, '\n'))
}
func Bytes(path string, data []byte) error {
	if err := Dir(filepath.Dir(path)); err != nil {
		return err
	}
	if i, err := os.Lstat(path); err == nil && (!i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0) {
		return errors.New("refusing to replace a non-regular file")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".write-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err == nil {
		defer d.Close()
		_ = d.Sync()
	}
	return nil
}
