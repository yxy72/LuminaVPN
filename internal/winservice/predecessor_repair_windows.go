//go:build windows && windows_client_predecessor_repair

package winservice

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"netlaunch/internal/platform"
)

const predecessorRepairReleaseID = "7a00c61756f23e96a5c14dfa6f62ea46c50990457161ecce304e7aee66985f16"

// PredecessorRepairExpectation identifies the original installation and run
// observed by the authorized acceptance controller.
type PredecessorRepairExpectation struct {
	ReleaseID       string `json:"release_id"`
	ServiceSHA256   string `json:"service_sha256"`
	LifecycleSHA256 string `json:"lifecycle_sha256"`
	OwnerSID        string `json:"owner_sid"`
	ProfileID       string `json:"profile_id"`
	ServiceInstance string `json:"service_instance"`
	RunRef          string `json:"run_ref"`
}

// PredecessorRepairHelperPath derives the acceptance helper path from native
// ProgramData and a fixed protected staging directory.
func PredecessorRepairHelperPath(nonce string) (string, error) {
	if !setupNonce.MatchString(nonce) {
		return "", errors.New("one exact predecessor repair nonce required")
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "LuminaVPN-PredecessorRepair", nonce, "lumina-validation-repair.exe"), nil
}

// RestoreUnpreparedPredecessor is available only in the separate acceptance
// recovery helper. It never starts or reconfigures an SCM service, or writes a
// recovery acknowledgement or installer retirement journal.
func RestoreUnpreparedPredecessor(ctx context.Context, expected PredecessorRepairExpectation, verifyExited func(platform.Identity, string) error, abort func(context.Context, Binding, Installation, func(profile, runRef, instance, runID, lifecycleSHA, expectedSpecDigest string) (bool, error)) (json.RawMessage, error)) (InstallResult, error) {
	result := InstallResult{Action: "recover-unprepared-predecessor"}
	if ctx == nil || verifyExited == nil || abort == nil {
		return result, errors.New("fixed predecessor repair inputs required")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || user.User.Sid.String() != "S-1-5-18" {
		return result, errors.New("LocalSystem predecessor repair required")
	}
	self, err := os.Executable()
	if err != nil {
		return result, err
	}
	directory := filepath.Dir(self)
	imagePath, err := PredecessorRepairHelperPath(filepath.Base(directory))
	if err != nil || !strings.EqualFold(imagePath, filepath.Clean(self)) {
		return result, errors.New("fresh protected predecessor repair helper required")
	}
	if err = (WindowsProtectedFiles{Root: directory}).validatePath(imagePath); err != nil {
		return result, err
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return result, err
	}
	lock, err := acquireInstallerLock()
	if err != nil {
		return result, err
	}
	defer windows.CloseHandle(lock)
	installation, err := LoadInstallation()
	if err != nil {
		return result, err
	}
	system := &windowsInstallSystem{
		installation: installation, root: filepath.Join(base, "LuminaVPN", "ServiceState"),
		command: CommandRecover, ctx: ctx, installerLock: lock,
	}
	files := installedStateFiles{root: system.root}
	source, err := inspectUnpreparedPredecessor(system, files, expected)
	if err != nil {
		return result, err
	}
	image, err := system.installation.Executable(ServiceImage)
	if err != nil {
		return result, err
	}
	if err = verifyExited(platform.Identity{PID: source.ServiceHostPID, Birth: source.ServiceHostBirth, Executable: image, OwnerSID: source.ExecutorSID}, source.ServiceHostSHA256); err != nil {
		return result, err
	}
	owners, err := newFileOwnershipStore(files, source)
	if err != nil {
		return result, err
	}
	verifyHistorical := func(profile, runRef, instance, runID, lifecycleSHA, expectedSpecDigest string) (bool, error) {
		current, err := owners.Lookup(source.ProfileID)
		if err != nil || !samePredecessorBinding(current, source) {
			return false, errors.New("predecessor binding changed during historical readback")
		}
		return verifyHistoricalPreparationState(files, current, profile, runRef, instance, runID, lifecycleSHA, expectedSpecDigest)
	}
	started := time.Now()
	proof, err := abort(ctx, source, system.installation, verifyHistorical)
	if err != nil {
		return result, err
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	// Reopen the entire protected release before publishing a proof about its run.
	system.installation, err = LoadInstallation()
	if err != nil {
		return result, err
	}
	current, err := inspectUnpreparedPredecessor(system, files, expected)
	if err != nil {
		return result, err
	}
	if !samePredecessorBinding(current, source) {
		return result, errors.New("predecessor binding changed during preparation abort")
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = publishUnpreparedPredecessor(files, owners, source, proof, started, time.Now()); err != nil {
		return result, err
	}
	result.Completed, result.Restored = true, true
	return result, nil
}

func inspectUnpreparedPredecessor(system *windowsInstallSystem, files installedStateFiles, expected PredecessorRepairExpectation) (Binding, error) {
	installation := system.installation
	if expected.ReleaseID != predecessorRepairReleaseID || installation.release != expected.ReleaseID || !digestText.MatchString(expected.ServiceSHA256) || installation.pins[ServiceImage].SHA256 != expected.ServiceSHA256 || !digestText.MatchString(expected.LifecycleSHA256) || installation.pins[LifecycleImage].SHA256 != expected.LifecycleSHA256 {
		return Binding{}, errors.New("exact reviewed predecessor release required")
	}
	state, err := system.Inspect()
	if err != nil {
		return Binding{}, err
	}
	if !state.Present || !state.Trusted || !state.Enrolled || !state.ServicesMatch || state.Retired || state.BootstrapPending || state.UninstallPending {
		return Binding{}, errors.New("predecessor installation or SCM identity changed")
	}
	source := system.binding
	if err = validateUnpreparedPredecessor(source, expected, time.Now()); err != nil {
		return Binding{}, err
	}
	journal, exists, err := readInstallJournal(files)
	if err != nil {
		return Binding{}, err
	}
	image, digest, err := system.journalIdentity()
	if err != nil {
		return Binding{}, err
	}
	if !exists || journal.Action != "bootstrap" || journal.Phase != "complete" || journal.Image != image || journal.ReleaseDigest != digest || journal.Published == nil || !samePermanentEnrollment(*journal.Published, source) {
		return Binding{}, errors.New("complete exact predecessor bootstrap journal required")
	}
	if err = requirePredecessorServicesStopped(); err != nil {
		return Binding{}, err
	}
	return source, nil
}

func validateUnpreparedPredecessor(source Binding, expected PredecessorRepairExpectation, now time.Time) error {
	if !sidText.MatchString(expected.OwnerSID) || expected.OwnerSID == "S-1-5-18" || !ValidProfileID(expected.ProfileID) || !releaseText.MatchString(expected.ServiceInstance) || !releaseText.MatchString(expected.RunRef) || source.OwnerSID != expected.OwnerSID || source.ProfileID != expected.ProfileID || source.ServiceInstance != expected.ServiceInstance || source.RunRef != expected.RunRef {
		return errors.New("exact enrolled predecessor run required")
	}
	if source.ExecutorSID != "S-1-5-18" || source.PendingEnrollmentID != "" || source.Mode != "validation" || source.Deadline.IsZero() || !source.Deadline.Before(now) || source.PreparedRunID != "" || source.SpecDigest != "" {
		return errors.New("expired durably unprepared predecessor binding required")
	}
	if source.ServiceHostPID < 2 || uint64(source.ServiceHostPID) > uint64(^uint32(0)) || source.ServiceHostBirth == "" || source.ServiceHostSHA256 != expected.ServiceSHA256 || source.LifecycleSHA256 != expected.LifecycleSHA256 {
		return errors.New("exact predecessor service host and lifecycle pins required")
	}
	return nil
}

func requirePredecessorServicesStopped() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	for _, name := range []string{ServiceName, RecoveryServiceName} {
		service, err := manager.OpenService(name)
		if err != nil {
			return err
		}
		status, queryErr := service.Query()
		service.Close()
		if queryErr != nil || status.State != svc.Stopped || status.ProcessId != 0 {
			return errors.New("both predecessor SCM services must be observed stopped")
		}
	}
	return nil
}

func samePredecessorBinding(a, b Binding) bool {
	if !a.Deadline.Equal(b.Deadline) {
		return false
	}
	a.Deadline, b.Deadline = time.Time{}, time.Time{}
	return a == b
}

func publishUnpreparedPredecessor(files protectedStateFiles, owners *FileOwnershipStore, source Binding, proof json.RawMessage, started, now time.Time) error {
	var flags restorationFlags
	if !validRestorationProof("unprepared", proof) || json.Unmarshal(proof, &flags) != nil || flags.Started.Before(started) || flags.Finished.After(now) {
		return errors.New("fresh strict predecessor preparation-abort proof required")
	}
	proofs := &RestorationStore{files: files, enrolled: source}
	receipt, err := proofs.Save(source, "unprepared", proof)
	if err != nil {
		return err
	}
	restored := source
	clearRunBinding(&restored)
	restored.LastRestorationID = receipt
	if err = owners.Save(restored); err != nil {
		return err
	}
	current, err := owners.Lookup(source.ProfileID)
	if err != nil || current != restored {
		return errors.New("predecessor restoration publication could not be read back")
	}
	if clean, err := proofs.Verify(current); err != nil || !clean {
		return errors.New("strict predecessor restoration receipt could not be read back")
	}
	return nil
}
