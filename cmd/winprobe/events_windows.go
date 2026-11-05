//go:build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"netlaunch/internal/platform"
	"netlaunch/internal/securefile"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Each process/attempt has a separate private event file. Recovery must never
// overwrite a failed holder's evidence, including during a later manual run.
type probeEvents struct {
	mu        sync.Mutex
	files     securefile.AdminStore
	path      string
	actor     platform.Identity
	owner     platform.Identity
	watcher   platform.Identity
	role      string
	items     []map[string]any
	err       error
	nativeErr error
}

func newProbeEvents(files securefile.AdminStore, id, role string) (*probeEvents, error) {
	actor, err := platform.Process(os.Getpid())
	if err != nil {
		return nil, err
	}
	var p plan
	if err = read(files, id, "probe-plan.json", &p); err != nil {
		return nil, err
	}
	var watcher platform.Identity
	if err = read(files, id, "probe-watcher.json", &watcher); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	nonce := make([]byte, 8)
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	l := &probeEvents{files: files, path: filepath.Join(id, "probe-events-"+role+"-"+hex.EncodeToString(nonce)+".json"), actor: actor, owner: p.Owner, watcher: watcher, role: role}
	return l, l.add("process", "started", nil)
}

func (l *probeEvents) add(operation, phase string, details any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	if len(l.items) >= 512 {
		l.err = errors.New("probe event limit reached")
		return l.err
	}
	l.items = append(l.items, map[string]any{"time": time.Now(), "sequence": len(l.items) + 1, "operation": operation, "phase": phase, "details": details})
	l.err = l.files.Write(l.path, map[string]any{"actor": l.actor, "owner": l.owner, "watcher": l.watcher, "role": l.role, "events": l.items})
	return l.err
}

func (l *probeEvents) finish(operation string, err error) error {
	l.mu.Lock()
	nativeErr := l.nativeErr
	l.mu.Unlock()
	err = errors.Join(err, nativeErr)
	if err != nil {
		return errors.Join(err, l.add(operation, "error", map[string]any{"error": err.Error()}))
	}
	return l.add(operation, "completed", nil)
}

// Native error messages remain independently reportable: setting the storage
// error would suppress the subsequent EndSession/CloseAdapter event evidence.
func (l *probeEvents) recordNativeError(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nativeErr = errors.Join(l.nativeErr, err)
}

// Diagnostic storage is not cleanup authority. It may make validation fail,
// but must never prevent release of already journaled, owned resources.
func withProbeCleanupDiagnostics(open func() (*probeEvents, error), cleanup func(*probeEvents) error) error {
	log, err := open()
	if log == nil {
		log = &probeEvents{err: err}
	}
	if err != nil {
		log.err = err
	}
	cleanupErr := cleanup(log)
	return errors.Join(err, cleanupErr)
}
