//go:build windows

package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"netlaunch/internal/platform"
	"netlaunch/internal/winservice"
)

// VerifyServiceHostExited checks only the frozen original process. The recovery
// service must independently prove that the current SCM main service is stopped;
// an older PID's death does not prove that a newer main instance is quiescent.
func VerifyServiceHostExited(expected platform.Identity, imageSHA256 string) error {
	if !serviceDigest.MatchString(imageSHA256) {
		return errors.New("frozen service image pin missing")
	}
	return waitServiceHostExitedWith(expected, platform.Process, time.Now, time.Sleep)
}

func ServiceRecoveryHostExited(reference ServiceRunReference) error {
	_, manifest, err := ServiceManifest(reference)
	if err != nil {
		return err
	}
	if manifest.Service == nil {
		return errors.New("frozen service owner unavailable")
	}
	return VerifyServiceHostExited(manifest.Service.ServiceHost, manifest.Service.ServiceHostSHA256)
}

func waitServiceHostExitedWith(expected platform.Identity, query func(int) (platform.Identity, error), now func() time.Time, pause func(time.Duration)) error {
	if expected.PID < 2 || uint64(expected.PID) > uint64(^uint32(0)) || expected.Birth == "" || len(expected.Birth) > 256 || expected.OwnerSID != "S-1-5-18" || !filepath.IsAbs(expected.Executable) {
		return errors.New("frozen service owner identity incomplete")
	}
	deadline := now().Add(5 * time.Second)
	for attempt := 0; attempt < 100; attempt++ {
		if !now().Before(deadline) {
			return errors.New("original service owner exit was not confirmed in time")
		}
		actual, err := query(expected.PID)
		if err != nil || !now().Before(deadline) {
			return errors.New("original service owner observation unknown")
		}
		if actual == (platform.Identity{}) {
			return nil
		}
		if actual.PID != expected.PID || actual.Birth == "" || actual.OwnerSID == "" || !filepath.IsAbs(actual.Executable) {
			return errors.New("original service owner observation incomplete")
		}
		if actual.Birth != expected.Birth {
			// A different creation time proves the frozen process is gone. This
			// function never opens a termination handle or kills the reused PID.
			return nil
		}
		if !sameProcess(expected, actual) {
			return errors.New("original service owner observation conflicts")
		}
		pause(50 * time.Millisecond)
	}
	return errors.New("original service owner is still running")
}

func serviceHostAliveWith(binding ServiceRunBinding, query func(int) (platform.Identity, error)) error {
	if binding.ServiceHost.PID < 2 || binding.ServiceHost.Birth == "" || binding.ServiceHost.OwnerSID != "S-1-5-18" {
		return errors.New("service owner identity incomplete")
	}
	actual, err := query(binding.ServiceHost.PID)
	if err != nil {
		return errors.New("service owner native observation unknown")
	}
	if !sameProcess(binding.ServiceHost, actual) {
		return errors.New("service owner exited or identity changed")
	}
	return nil
}
func verifyServiceHostPin(binding ServiceRunBinding) error {
	if err := serviceHostAliveWith(binding, platform.Process); err != nil {
		return err
	}
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return err
	}
	root := filepath.Join(programFiles, "LuminaVPN")
	relative, err := filepath.Rel(root, binding.ServiceHost.Executable)
	if err != nil {
		return err
	}
	parts := strings.Split(relative, string(filepath.Separator))
	if len(parts) != 3 || !strings.EqualFold(parts[0], "releases") || !serviceProfileID.MatchString(parts[1]) || !strings.EqualFold(parts[2], "lumina-service.exe") {
		return errors.New("service owner is outside the fixed machine release")
	}
	data, err := (winservice.WindowsProtectedFiles{Root: root}).ReadProtected(binding.ServiceHost.Executable)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != binding.ServiceHostSHA256 {
		return errors.New("service owner differs from frozen release pin")
	}
	return nil
}
