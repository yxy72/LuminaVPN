//go:build darwin || linux

package securefile

import (
	"errors"
	"os"
	"syscall"
	"time"
)

func Lock(path string, timeout time.Duration) (func(), error) {
	return lockUnix(path, timeout, syscall.O_CREAT)
}

// LockExisting avoids creating a root-owned lock in a user's profile when
// an administrator performs maintenance. Normal startup creates that lock.
func LockExisting(path string, timeout time.Duration) (func(), error) {
	return lockUnix(path, timeout, 0)
}

func lockUnix(path string, timeout time.Duration, create int) (func(), error) {
	fd, err := syscall.Open(path, create|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	deadline := time.Now().Add(timeout)
	for {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) || time.Now().After(deadline) {
			f.Close()
			return nil, errors.New("state is busy")
		}
		time.Sleep(25 * time.Millisecond)
	}
}
