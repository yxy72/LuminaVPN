package winservice

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
)

type resumeInstallPreflightControl struct {
	acquire func() (func(), error)
	journal func() (installJournal, bool, error)
	pending func(context.Context, installJournal) (InstallSystem, error)
}

// The public installer invokes this before NSIS runs an earlier uninstaller.
// A held installer lock covers both observations and the entire exact repair.
// Nonpending cases never construct an installed system or load a release.
func resumeInstallPreflight(ctx context.Context, control resumeInstallPreflightControl) (InstallResult, error) {
	result := InstallResult{Action: "resume-install-preflight"}
	if control.acquire == nil || control.journal == nil || control.pending == nil {
		return result, errors.New("fixed resume preflight control unavailable")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	release, err := control.acquire()
	if err != nil {
		return result, err
	}
	if release == nil {
		return result, errors.New("resume preflight has no installer lock")
	}
	defer release()
	j, exists, err := control.journal()
	if err != nil {
		return result, err
	}
	if exists {
		if err = validateInstallJournal(j); err != nil {
			return result, err
		}
	}
	if !exists || j.Action == "retire" || j.Phase == "complete" {
		result.Completed = true
		return result, nil
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	system, err := control.pending(ctx, j)
	if err != nil {
		return result, err
	}
	if system == nil {
		return result, errors.New("pending installer system unavailable")
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	result, err = Bootstrap(ctx, system)
	result.Action = "resume-install-preflight"
	return result, err
}

type resumeInstallerEvidence struct {
	Image, ReleaseDigest, HelperSHA256, ServiceSHA256 string
	Enrollment                                        Binding
}

func verifyPendingResume(j installJournal, evidence resumeInstallerEvidence) error {
	if validateInstallJournal(j) != nil || j.Action != "bootstrap" || j.Phase == "complete" || j.Image != evidence.Image || j.ReleaseDigest != evidence.ReleaseDigest || !digestText.MatchString(evidence.HelperSHA256) || !digestText.MatchString(evidence.ServiceSHA256) || evidence.HelperSHA256 != evidence.ServiceSHA256 || !journalCallerMatches(j, evidence.Enrollment) {
		return errors.New("pending installer release, helper or original login changed")
	}
	return nil
}

// This entry is deliberately stricter than ValidateInstallerImage's legacy
// installed-image fallback: only the fresh fixed setup nonce may invoke it.
func resumeBootstrapNoncePath(self, programData string) bool {
	if !filepath.IsAbs(self) || filepath.Clean(self) != self {
		return false
	}
	directory := filepath.Dir(self)
	return strings.EqualFold(filepath.Dir(directory), filepath.Join(programData, "LuminaVPN-Setup")) && filepath.Base(self) == "lumina-service.exe" && setupNonce.MatchString(filepath.Base(directory))
}
