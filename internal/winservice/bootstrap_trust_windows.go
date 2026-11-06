//go:build windows

package winservice

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// ValidateInstallerImage is a second check after the trusted installer's
// native pre-execution pin/ACL/handle checks. It cannot replace those checks.
// No executable from an unknown existing target tree is ever launched here.
func ValidateInstallerImage() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self = filepath.Clean(self)
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return err
	}
	setup := filepath.Join(base, "LuminaVPN-Setup")
	directory := filepath.Dir(self)
	nonce := filepath.Base(directory)
	if strings.EqualFold(filepath.Dir(directory), setup) && filepath.Base(self) == "lumina-service.exe" && setupNonce.MatchString(nonce) {
		files := WindowsProtectedFiles{Root: directory}
		data, err := files.ReadProtected(filepath.Join(directory, BootstrapTrustFile))
		if err != nil {
			return err
		}
		var trust BootstrapTrust
		if decodeState(data, &trust) != nil || trust.Validate(nonce, time.Now()) != nil {
			return errors.New("invalid fresh bootstrap trust")
		}
		data, err = files.ReadProtected(self)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != trust.SHA256 {
			return errors.New("bootstrap image differs from installer resource pin")
		}
		return nil
	}
	installation, err := LoadInstallation()
	if err != nil {
		return err
	}
	expected, err := installation.Executable(ServiceImage)
	if err != nil || !strings.EqualFold(self, expected) {
		return errors.New("fixed protected installer image required")
	}
	_, err = installation.ReadProtectedExecutable(ServiceImage)
	return err
}

func targetPreflight(root string) string {
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		for parent := filepath.Dir(root); ; parent = filepath.Dir(parent) {
			name, parseErr := windows.UTF16PtrFromString(parent)
			if parseErr != nil {
				return "unsafe"
			}
			attributes, attrErr := windows.GetFileAttributes(name)
			if attrErr != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || checkACLMask(parent, ancestorReplaceMask) != nil {
				return "unsafe"
			}
			if filepath.Dir(parent) == parent {
				break
			}
		}
		return "absent"
	} else if err != nil {
		return "unsafe"
	}
	files := WindowsProtectedFiles{Root: root}
	count := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		count++
		if count > 4096 {
			return errors.New("target inventory limit")
		}
		return files.validatePath(path)
	})
	if err != nil {
		return "unsafe"
	}
	return "protected"
}
func InstallerPlan() (InstallPlan, error) {
	// Public read-only preflight: it may run from a compiler/build staging
	// location. It never installs, enrolls, executes a target or changes ACLs.
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return InstallPlan{}, err
	}
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return InstallPlan{}, err
	}
	return installerPlanModel(programFiles, programData, targetPreflight, legacyUninstallPreflight), nil
}
