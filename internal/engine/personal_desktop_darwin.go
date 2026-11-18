//go:build darwin

package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/serviceprotocol"
)

var errDarwinPersonalRequestCanceled = errors.New("macOS personal request was canceled")

type DarwinDesktopPersonalRequest struct {
	ID                string
	Generation        uint64
	Device            int32
	Inode             uint64
	Company, Personal bool
}

func DarwinPersonalPermitName(id string) string { return "personal-permit-" + id }

func darwinPersonalPermit(run, id string) bool {
	return serviceprotocol.ValidID(id) && darwinLockedPermit(filepath.Join(run, DarwinPersonalPermitName(id)))
}

func (r DarwinDesktopPersonalRequest) valid() bool {
	return serviceprotocol.ValidID(r.ID) && r.Generation != 0 && r.Generation != ^uint64(0) && r.Inode != 0
}

func LaunchDarwinDesktopPersonal(ctx context.Context, run string, r DarwinDesktopPersonalRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateRun(run); err != nil {
		return err
	}
	if !r.valid() || !darwinPersonalPermit(run, r.ID) {
		return errors.New("invalid desktop personal request binding")
	}
	if managed, err := requestDarwinServiceRun(ctx, run, darwinServiceRequest{Action: "personal", Personal: &r}); managed {
		return err
	}
	switchValue := func(v bool) string {
		if v {
			return "on"
		}
		return "off"
	}
	parts := []string{
		filepath.Join(private(run), "netlaunch"), "_personal-intent", "--run", run, "--request-id", r.ID,
		"--expected-generation", strconv.FormatUint(r.Generation, 10), "--personal", switchValue(r.Personal),
		"--expected-company", switchValue(r.Company), "--device", strconv.FormatInt(int64(r.Device), 10),
		"--inode", strconv.FormatUint(r.Inode, 10),
	}
	for i := range parts {
		parts[i] = shellQuote(parts[i])
	}
	return runDarwinAuthorization(ctx, "umask 077; cd /private/tmp && "+strings.Join(parts, " "))
}

func (r DarwinDesktopPersonalRequest) matches(record *darwinPersonalControl) bool {
	return record != nil && record.RequestID == r.ID && record.RequestGeneration == r.Generation &&
		record.Enabled == r.Personal && record.Company == r.Company
}

func ApplyDarwinDesktopPersonal(run string, r DarwinDesktopPersonalRequest) error {
	if !r.valid() {
		return errors.New("invalid desktop personal request binding")
	}
	check := func(s State) error {
		if err := checkDarwinCompanyOwner(run, s); err != nil {
			return err
		}
		info, err := os.Lstat(run)
		if err != nil {
			return err
		}
		id, ok := info.Sys().(*syscall.Stat_t)
		if !ok || id.Dev != r.Device || id.Ino != r.Inode {
			return errors.New("selected macOS run directory changed")
		}
		if !darwinPersonalPermit(run, r.ID) {
			return errDarwinPersonalRequestCanceled
		}
		return nil
	}
	if err := update(run, func(s *State) error {
		if err := check(*s); err != nil {
			return err
		}
		runner, err := platform.Process(s.Runner.PID)
		if err != nil || runner != s.Runner {
			return errors.New("administrator coordinator no longer matches the active run")
		}
		if err := check(*s); err != nil {
			return err
		}
		return queueDarwinPersonalChange(s, r)
	}); err != nil {
		return err
	}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		s, err := load(run)
		if err != nil {
			return err
		}
		if err := check(s); err != nil {
			return err
		}
		if done, err := darwinDesktopPersonalApplied(s, r); done || err != nil {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("macOS personal change readback timed out")
}

func darwinDesktopPersonalApplied(s State, r DarwinDesktopPersonalRequest) (bool, error) {
	record := s.DarwinPersonal
	if !r.matches(record) || record.Failed {
		return false, errors.New("desktop personal change was canceled or could not be applied")
	}
	if record.Pending {
		return false, nil
	}
	if !s.TakeoverActive || s.ChannelGeneration != r.Generation+1 || s.AppliedGeneration != s.ChannelGeneration ||
		s.DesiredChannels == nil || s.AppliedChannels == nil || *s.DesiredChannels != *s.AppliedChannels ||
		s.AppliedChannels.Company != r.Company || s.AppliedChannels.Personal != r.Personal || s.PersonalFallback ||
		r.Personal && (s.Personal == "PHYSICAL" || s.Personal == "") || !r.Personal && s.Personal != "PHYSICAL" {
		return false, errors.New("desktop personal command lacks exact applied generation")
	}
	return true, nil
}
