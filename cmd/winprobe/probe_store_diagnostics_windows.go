//go:build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"netlaunch/internal/securefile"
	"netlaunch/internal/winstate"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The ownership journal is authoritative and must be durable before cleanup.
// A stopping run's optional transition trace must not prevent later cleanup;
// its failure instead makes the final recovery outcome fail verification.
func saveProbeJournalWithDiagnostics(j winstate.Journal, save func(winstate.Journal) error, diagnostics func(winstate.Journal) error, record func(error)) error {
	if err := save(j); err != nil {
		return err
	}
	if err := diagnostics(j); err != nil {
		if !j.Stopping {
			return err
		}
		record(err)
	}
	return nil
}

type probeDiagnosticFailure struct {
	Version   int       `json:"version"`
	Operation string    `json:"operation"`
	Stopping  bool      `json:"stopping"`
	Time      time.Time `json:"time"`
	Error     string    `json:"error"`
}

var probeDiagnosticPending = struct {
	sync.Mutex
	errors map[string]error
}{errors: make(map[string]error)}

func probeDiagnosticKey(files securefile.AdminStore, id string) string {
	return strings.ToLower(filepath.Clean(filepath.Join(files.Root, id)))
}

func rememberProbeDiagnosticFailure(files securefile.AdminStore, id string, err error) bool {
	key := probeDiagnosticKey(files, id)
	probeDiagnosticPending.Lock()
	defer probeDiagnosticPending.Unlock()
	if probeDiagnosticPending.errors[key] == nil {
		probeDiagnosticPending.errors[key] = err
		return true
	}
	return false
}

func recordProbeDiagnosticFailure(files securefile.AdminStore, id string, err error) {
	recordProbeDiagnosticFailureWith(files, id, err, files.Write, rand.Read)
}

func recordProbeDiagnosticFailureWith(files securefile.AdminStore, id string, err error, writeFile func(string, any) error, random func([]byte) (int, error)) {
	failure := fmt.Errorf("probe transition diagnostic failed during stopping: %w", err)
	// Keep the error in this process even if the separate diagnostic write fails.
	// The recovery finalizer checks it after all ownership-checked cleanup.
	if !rememberProbeDiagnosticFailure(files, id, failure) {
		return // One durable marker per process/run bounds repeated Save failures.
	}
	nonce := make([]byte, 16)
	if _, randomErr := random(nonce); randomErr != nil {
		rememberProbeDiagnosticWriteFailure(files, id, randomErr)
		return
	}
	name := "probe-diagnostic-failure-" + hex.EncodeToString(nonce) + ".json"
	text := failure.Error()
	if len(text) > 4096 {
		text = text[:4096]
	}
	if writeErr := writeFile(filepath.Join(id, name), probeDiagnosticFailure{
		Version: 1, Operation: "probe-transitions", Stopping: true, Time: time.Now(), Error: text,
	}); writeErr != nil {
		rememberProbeDiagnosticWriteFailure(files, id, writeErr)
	}
}

func rememberProbeDiagnosticWriteFailure(files securefile.AdminStore, id string, err error) {
	key := probeDiagnosticKey(files, id)
	probeDiagnosticPending.Lock()
	defer probeDiagnosticPending.Unlock()
	probeDiagnosticPending.errors[key] = errors.Join(probeDiagnosticPending.errors[key], fmt.Errorf("persist probe diagnostic failure: %w", err))
}

// Called by recoverProbe's finalizer, after cleanup and before its outcome is
// persisted. Markers survive later manual recovery; they are never deleted.
func checkProbeDiagnosticFailures(files securefile.AdminStore, id string) error {
	if !validID.MatchString(id) {
		return errors.New("invalid diagnostic run identifier")
	}
	return checkProbeDiagnosticFailuresWith(files, id, func() ([]os.DirEntry, error) {
		return os.ReadDir(filepath.Join(files.Root, id))
	}, files.Read)
}

func checkProbeDiagnosticFailuresWith(files securefile.AdminStore, id string, entries func() ([]os.DirEntry, error), readFile func(string, int64) ([]byte, error)) error {
	key := probeDiagnosticKey(files, id)
	probeDiagnosticPending.Lock()
	pending := probeDiagnosticPending.errors[key]
	probeDiagnosticPending.Unlock()
	items, err := entries()
	if err != nil {
		return errors.Join(pending, fmt.Errorf("enumerate probe diagnostic failures: %w", err))
	}
	failures := []error{pending}
	for _, entry := range items {
		name := entry.Name()
		if !strings.HasPrefix(name, "probe-diagnostic-failure-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		data, err := readFile(filepath.Join(id, name), 64<<10)
		if err != nil {
			failures = append(failures, fmt.Errorf("read private diagnostic failure %s: %w", name, err))
			continue
		}
		var failure probeDiagnosticFailure
		if err = json.Unmarshal(data, &failure); err != nil || failure.Version != 1 || failure.Error == "" || !failure.Stopping {
			failures = append(failures, fmt.Errorf("invalid private probe diagnostic failure %s", name))
			continue
		}
		failures = append(failures, fmt.Errorf("private probe diagnostic failure %s: %s", name, failure.Error))
	}
	return errors.Join(failures...)
}
