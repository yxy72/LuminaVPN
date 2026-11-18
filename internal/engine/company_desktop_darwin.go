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

var errDarwinCompanyRequestCanceled = errors.New("macOS company request was canceled")

type DarwinDesktopCompanyRequest struct {
	ID                string
	Generation        uint64
	Device            int32
	Inode             uint64
	Company, Personal bool
}

func DarwinCompanyPermitName(id string) string { return "company-permit-" + id }

func darwinCompanyPermit(run, id string) bool {
	return serviceprotocol.ValidID(id) && darwinLockedPermit(filepath.Join(run, DarwinCompanyPermitName(id)))
}

func darwinLockedPermit(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != 0 {
		return false
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return false
	}
	return errors.Is(syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB), syscall.EWOULDBLOCK)
}

func LaunchDarwinDesktopCompany(ctx context.Context, run string, r DarwinDesktopCompanyRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateRun(run); err != nil {
		return err
	}
	if !serviceprotocol.ValidID(r.ID) || r.Generation == 0 || r.Inode == 0 || !darwinCompanyPermit(run, r.ID) {
		return errors.New("invalid desktop company request binding")
	}
	if managed, err := requestDarwinServiceRun(ctx, run, darwinServiceRequest{Action: "company", Company: &r}); managed {
		return err
	}
	switchValue := func(v bool) string {
		if v {
			return "on"
		}
		return "off"
	}
	parts := []string{
		filepath.Join(private(run), "netlaunch"), "_company-intent", "--run", run, "--request-id", r.ID,
		"--expected-generation", strconv.FormatUint(r.Generation, 10), "--company", switchValue(r.Company),
		"--expected-personal", switchValue(r.Personal), "--device", strconv.FormatInt(int64(r.Device), 10),
		"--inode", strconv.FormatUint(r.Inode, 10),
	}
	for i := range parts {
		parts[i] = shellQuote(parts[i])
	}
	return runDarwinAuthorization(ctx, "umask 077; cd /private/tmp && "+strings.Join(parts, " "))
}

// The native readback comes from the same protected journal as the mutation.
// A user-readable report cannot satisfy a desktop operation.
func ApplyDarwinDesktopCompany(run string, r DarwinDesktopCompanyRequest) error {
	if !serviceprotocol.ValidID(r.ID) || r.Generation == 0 || r.Generation == ^uint64(0) || r.Inode == 0 {
		return errors.New("invalid desktop company request binding")
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
		if !darwinCompanyPermit(run, r.ID) {
			return errDarwinCompanyRequestCanceled
		}
		return nil
	}
	if err := update(run, func(s *State) error {
		if err := check(*s); err != nil {
			return err
		}
		runner, err := platform.Process(s.Runner.PID)
		if err != nil || runner != s.Runner || currentIntent(*s).Personal != r.Personal || currentIntent(*s).Company == r.Company {
			return errors.New("desktop company request no longer matches the active run")
		}
		if err := check(*s); err != nil {
			return err
		}
		if err := queueDarwinCompanyChange(s, r.ID, r.Generation, r.Company); err != nil {
			return err
		}
		s.DarwinCompany.DesktopBound = true
		return nil
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
		if done, err := darwinDesktopCompanyApplied(s, r); done || err != nil {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("macOS company change readback timed out")
}

func darwinDesktopCompanyApplied(s State, r DarwinDesktopCompanyRequest) (bool, error) {
	record := s.DarwinCompany
	if record == nil || record.RequestID != r.ID || record.RequestGeneration != r.Generation || !record.DesktopBound || record.Enabled != r.Company {
		return false, errors.New("desktop company request no longer owns the transition")
	}
	if record.Pending {
		return false, nil
	}
	if !s.TakeoverActive || s.ChannelGeneration != r.Generation+1 || s.AppliedGeneration != s.ChannelGeneration ||
		s.DesiredChannels == nil || s.AppliedChannels == nil || *s.DesiredChannels != *s.AppliedChannels ||
		s.AppliedChannels.Company != r.Company || s.AppliedChannels.Personal != r.Personal {
		return false, errors.New("desktop company command lacks exact applied generation")
	}
	return true, nil
}
