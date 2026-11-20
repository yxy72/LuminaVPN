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

var errReadIdentityChanged = errors.New("file identity changed while opening")

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

// ReadAtomicSnapshot retries a private file read if an atomic publisher replaced
// the file between the path check and opening it. Use it for snapshots under a
// trusted parent; each attempt still performs all of the normal read checks.
func ReadAtomicSnapshot(path string, limit int64) ([]byte, error) {
	return readAtomicSnapshot(path, limit, openBoundedRead)
}

func readAtomicSnapshot(path string, limit int64, open func(string) (*os.File, error)) ([]byte, error) {
	for range 3 {
		data, err := readBoundedWithOpen(path, limit, true, false, open)
		if !errors.Is(err, errReadIdentityChanged) {
			return data, err
		}
	}
	return nil, errReadIdentityChanged
}

// ReadTail reads at most limit bytes from the end of a verified regular file.
// It uses the same identity and permission checks as Read, without loading a
// potentially long-lived component log into memory.
func ReadTail(path string, limit int64, private bool) ([]byte, error) {
	return readBounded(path, limit, private, true)
}

func readBounded(path string, limit int64, private, tail bool) ([]byte, error) {
	return readBoundedWithOpen(path, limit, private, tail, openBoundedRead)
}

func readBoundedWithOpen(path string, limit int64, private, tail bool, open func(string) (*os.File, error)) ([]byte, error) {
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
	f, err := open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) {
		return nil, errReadIdentityChanged
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
	return write(path, v, -1)
}

// WriteOwned sets the ownership on the open temporary file before publishing it.
func WriteOwned(path string, v any, owner int) error {
	return write(path, v, owner)
}

func write(path string, v any, owner int) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeBytes(path, append(b, '\n'), owner)
}
func Bytes(path string, data []byte) error {
	return writeBytes(path, data, -1)
}
func writeBytes(path string, data []byte, owner int) error {
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
	if err == nil && owner >= 0 {
		err = f.Chown(owner, -1)
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
