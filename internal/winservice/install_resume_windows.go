//go:build windows

package winservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func runWindowsResumePreflight(ctx context.Context) (InstallResult, error) {
	result := InstallResult{Action: "resume-install-preflight"}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return result, err
	}
	self, err := os.Executable()
	if err != nil {
		return result, err
	}
	self = filepath.Clean(self)
	if !resumeBootstrapNoncePath(self, base) {
		return result, errors.New("resume preflight requires the fresh protected setup nonce")
	}
	// The path predicate above prevents this call taking its installed-PF
	// fallback. It must verify the fresh nonce envelope and resource-pinned image.
	if err = ValidateInstallerImage(); err != nil {
		return result, err
	}
	if err = requireInstallerAdministrator(); err != nil {
		return result, err
	}
	imageBytes, err := (WindowsProtectedFiles{Root: filepath.Dir(self)}).ReadProtected(self)
	if err != nil {
		return result, err
	}
	sum := sha256.Sum256(imageBytes)
	helperSHA := hex.EncodeToString(sum[:])
	root := filepath.Join(base, "LuminaVPN", "ServiceState")
	var held windows.Handle
	return resumeInstallPreflight(ctx, resumeInstallPreflightControl{
		// Claim only this product's fixed registry leaves, after successful
		// journal/resume validation and while the same installer lock is held.
		finalize: func() error { return claimFixedMachineRegistry(ctx) },
		acquire: func() (func(), error) {
			var err error
			held, err = acquireInstallerLock()
			if err != nil {
				return nil, err
			}
			return func() { windows.CloseHandle(held) }, nil
		},
		journal: func() (installJournal, bool, error) {
			return readResumeInstallerJournal(root)
		},
		pending: func(ctx context.Context, j installJournal) (InstallSystem, error) {
			// No release load, ordinary-token capture, SCM observation or repair
			// occurs on fresh/complete/retirement preflight paths.
			installation, err := LoadInstallation()
			if err != nil {
				return nil, err
			}
			system := &windowsInstallSystem{installation: installation, root: root, command: CommandBootstrap, ctx: ctx, installerLock: held}
			image, digest, err := system.journalIdentity()
			if err != nil {
				return nil, err
			}
			enrollment, err := captureInstallerEnrollment()
			if err != nil {
				return nil, err
			}
			if err = verifyPendingResume(j, resumeInstallerEvidence{Image: image, ReleaseDigest: digest, HelperSHA256: helperSHA, ServiceSHA256: installation.pins[ServiceImage].SHA256, Enrollment: enrollment}); err != nil {
				return nil, err
			}
			system.enrollment = &enrollment
			// Bootstrap.Inspect independently rereads the protected journal,
			// enrollment/proofs and full SCM prefix while this same lock is held.
			return system, nil
		},
	})
}

func readResumeInstallerJournal(root string) (installJournal, bool, error) {
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		// A first installation has no ServiceState parent to validate through
		// installedStateFiles.Read. Verify the existing native ancestors without
		// creating any directory; all other failures remain unknown, not absent.
		for current := filepath.Dir(root); ; current = filepath.Dir(current) {
			name, err := windows.UTF16PtrFromString(current)
			if err != nil {
				return installJournal{}, true, err
			}
			attributes, attrErr := windows.GetFileAttributes(name)
			if attrErr == nil {
				if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
					return installJournal{}, true, errors.New("resume preflight ancestor is unverified or reparse")
				}
				if err = checkACLMask(current, ancestorReplaceMask); err != nil {
					return installJournal{}, true, err
				}
			} else if !errors.Is(attrErr, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(attrErr, windows.ERROR_PATH_NOT_FOUND) {
				return installJournal{}, true, attrErr
			}
			if filepath.Dir(current) == current {
				if attrErr != nil {
					return installJournal{}, true, attrErr
				}
				break
			}
		}
		return installJournal{}, false, nil
	}
	if err != nil {
		return installJournal{}, true, err
	}
	if !info.IsDir() {
		return installJournal{}, true, errors.New("resume preflight state root is not a directory")
	}
	if err = (WindowsProtectedFiles{Root: root}).validatePath(root); err != nil {
		return installJournal{}, true, err
	}
	return readInstallJournal(installedStateFiles{root: root})
}
