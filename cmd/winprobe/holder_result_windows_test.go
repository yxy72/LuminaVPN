//go:build windows

package main

import (
	"errors"
	"netlaunch/internal/platform"
	"os"
	"strings"
	"testing"
	"time"
)

func probeHolderIdentityFixture() platform.Identity {
	return platform.Identity{PID: 42, Birth: "1dd6d095cf958f4", Executable: `C:\owned-run\winprobe.exe`, OwnerSID: "S-1-5-21-fixture"}
}

func TestProbeHolderResultIncludesFinalLogError(t *testing.T) {
	logErr := errors.New("private holder event write failed")
	log := &probeEvents{err: logErr}
	result := makeProbeHolderResult(probeHolderIdentityFixture(), log.finish("holder", nil), time.Unix(1, 0))
	if result.Clean || !strings.Contains(result.Error, logErr.Error()) {
		t.Fatal("failed final diagnostics were reported clean", result)
	}
}

func TestProbeHolderTerminalResultRequiresCompleteCleanEvidence(t *testing.T) {
	expected := probeHolderIdentityFixture()
	clean := makeProbeHolderResult(expected, nil, time.Unix(1, 0))
	for _, tt := range []struct {
		name    string
		result  probeHolderResult
		loadErr error
		wantErr bool
	}{
		{name: "normal marker", result: clean},
		{name: "missing marker", loadErr: os.ErrNotExist, wantErr: true},
		{name: "unreadable marker", loadErr: errors.New("invalid JSON"), wantErr: true},
		{name: "abnormal marker", result: makeProbeHolderResult(expected, errors.New("holder did not return normally"), time.Unix(1, 0)), wantErr: true},
		{name: "false clean flag", result: probeHolderResult{Holder: expected, Finished: time.Unix(1, 0)}, wantErr: true},
		{name: "error contradicts clean flag", result: probeHolderResult{Holder: expected, Finished: time.Unix(1, 0), Clean: true, Error: "close failed"}, wantErr: true},
		{name: "no completion time", result: probeHolderResult{Holder: expected, Clean: true}, wantErr: true},
		{name: "incomplete holder", result: probeHolderResult{Holder: platform.Identity{PID: expected.PID}, Finished: time.Unix(1, 0), Clean: true}, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := checkProbeHolderResult(expected, func() (probeHolderResult, error) { return tt.result, tt.loadErr })
			if (err != nil) != tt.wantErr {
				t.Fatal(err)
			}
			if tt.loadErr != nil && !errors.Is(err, tt.loadErr) {
				t.Fatal("lost marker read failure", err)
			}
		})
	}
}

func TestProbeHolderTerminalResultRejectsIdentityReuse(t *testing.T) {
	expected := probeHolderIdentityFixture()
	for _, mutate := range []func(*platform.Identity){
		func(i *platform.Identity) { i.PID++ },
		func(i *platform.Identity) { i.Birth += "-reused" },
		func(i *platform.Identity) { i.Executable += ".other" },
		func(i *platform.Identity) { i.OwnerSID += "-other" },
		func(i *platform.Identity) { i.Command = "unpublished command" },
	} {
		actual := expected
		mutate(&actual)
		result := makeProbeHolderResult(actual, nil, time.Unix(1, 0))
		if err := checkProbeHolderResult(expected, func() (probeHolderResult, error) { return result, nil }); err == nil {
			t.Fatal("changed holder identity passed", actual)
		}
	}
}

func TestProbeHolderMarkerFailureDoesNotSkipCleanup(t *testing.T) {
	cleanupErr, markerErr := errors.New("adapter remains present"), errors.New("missing holder marker")
	for _, failCleanup := range []bool{false, true} {
		var calls []string
		err := withProbeHolderResultCheck(func() error {
			calls = append(calls, "cleanup")
			if failCleanup {
				return cleanupErr
			}
			return nil
		}, func() error {
			calls = append(calls, "check marker")
			return markerErr
		})
		if strings.Join(calls, ",") != "cleanup,check marker" || !errors.Is(err, markerErr) || errors.Is(err, cleanupErr) != failCleanup {
			t.Fatal("terminal evidence skipped cleanup or lost errors", calls, err)
		}
	}
}

func TestProbeHolderResultCannotMarkIncompleteExitClean(t *testing.T) {
	for _, result := range []probeHolderResult{
		makeProbeHolderResult(platform.Identity{}, nil, time.Unix(1, 0)),
		makeProbeHolderResult(probeHolderIdentityFixture(), nil, time.Time{}),
	} {
		if result.Clean || result.Error == "" {
			t.Fatal("incomplete terminal evidence marked clean", result)
		}
	}
}
