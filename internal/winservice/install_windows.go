//go:build windows

package winservice

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"netlaunch/internal/winprofile"
)

type windowsInstallSystem struct {
	installation  Installation
	root          string
	enrollment    *Binding
	control       machineControl
	binding       Binding
	retired       bool
	recoveryNonce string
	mainDead      bool
	command       Command
	ctx           context.Context
	journal       *installJournal
	installerLock windows.Handle
}

func requireInstallerAdministrator() error {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	enabledAdmin, denyOnly := false, false
	if user.User.Sid.String() != "S-1-5-18" {
		groups, groupErr := token.GetTokenGroups()
		if groupErr != nil {
			return groupErr
		}
		for _, group := range groups.AllGroups() {
			if group.Sid.String() == "S-1-5-32-544" {
				enabledAdmin = group.Attributes&windows.SE_GROUP_ENABLED != 0
				denyOnly = group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0
			}
		}
	}
	elevated := false
	if user.User.Sid.String() != "S-1-5-18" {
		elevated, err = explicitTokenElevation(token)
		if err != nil {
			return err
		}
	}
	if !installerAdministrator(user.User.Sid.String(), elevated, enabledAdmin, denyOnly) {
		return errors.New("reviewed elevated installer context required")
	}
	return nil
}

func newWindowsInstallSystem(command Command) (*windowsInstallSystem, error) {
	if err := ValidateInstallerImage(); err != nil {
		return nil, err
	}
	if err := requireInstallerAdministrator(); err != nil {
		return nil, err
	}
	installation, err := LoadInstallation()
	if err != nil {
		return nil, err
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return nil, err
	}
	system := &windowsInstallSystem{installation: installation, root: filepath.Join(base, "LuminaVPN", "ServiceState"), command: command}
	if command == CommandBootstrap {
		binding, err := captureInstallerEnrollment()
		if err != nil {
			return nil, err
		}
		system.enrollment = &binding
	}
	system.installerLock, err = acquireInstallerLock()
	if err != nil {
		return nil, err
	}
	return system, nil
}
func RunInstallerCommand(ctx context.Context, command Command) (InstallResult, error) {
	if command == CommandResumePreflight {
		return runWindowsResumePreflight(ctx)
	}
	if command != CommandBootstrap && command != CommandUninstall && command != CommandRecover {
		return InstallResult{}, errors.New("fixed administrative entry required")
	}
	system, err := newWindowsInstallSystem(command)
	if err != nil {
		return InstallResult{}, err
	}
	defer windows.CloseHandle(system.installerLock)
	system.ctx = ctx
	switch command {
	case CommandBootstrap:
		return Bootstrap(ctx, system)
	case CommandUninstall:
		return Uninstall(ctx, system)
	case CommandRecover:
		state, err := system.Inspect()
		if err != nil || !state.Trusted || !state.Enrolled || !state.ServicesMatch {
			return InstallResult{}, errors.New("known protected recovery installation required")
		}
		_ = system.StopMain(ctx)
		if err = system.RecoverExact(ctx); err != nil {
			return InstallResult{}, err
		}
		return InstallResult{Action: "recover", Completed: true, Restored: true}, nil
	}
	return InstallResult{}, errors.New("unsupported installer operation")
}
func serviceConfigMatches(service *mgr.Service, image, argument string, automatic bool) bool {
	name := RecoveryServiceName
	if automatic {
		name = ServiceName
	}
	want, _, _, err := fixedJournalService(name)
	return err == nil && argument == want && knownJournalServiceConfig(service, image, name, false) == nil
}
func (s *windowsInstallSystem) Inspect() (BootstrapState, error) {
	image, err := s.installation.Executable(ServiceImage)
	if err != nil {
		return BootstrapState{}, err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return BootstrapState{}, err
	}
	defer manager.Disconnect()
	main, mainErr := manager.OpenService(ServiceName)
	if mainErr == nil {
		defer main.Close()
	}
	recovery, recoveryErr := manager.OpenService(RecoveryServiceName)
	if recoveryErr == nil {
		defer recovery.Close()
	}
	_, stateErr := os.Lstat(s.root)
	if errors.Is(stateErr, os.ErrNotExist) && errors.Is(mainErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) && errors.Is(recoveryErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return BootstrapState{}, nil
	}
	state := BootstrapState{Present: true}
	if stateErr != nil {
		return state, errors.New("unknown existing machine state")
	}
	files := installedStateFiles{root: s.root}
	if state, handled, err := s.inspectInstallerJournal(files, manager); handled {
		return state, err
	}
	data, err := files.Read("machine-control.json")
	if err != nil {
		return state, err
	}
	if decodeState(data, &s.control) != nil {
		return state, errors.New("unknown existing control schema")
	}
	expected, err := s.control.binding()
	if err != nil {
		return state, err
	}
	owners, err := newFileOwnershipStore(files, expected)
	if err != nil {
		return state, err
	}
	s.binding, err = owners.Lookup(expected.ProfileID)
	if err != nil {
		return state, err
	}
	state.Trusted = true
	state.Enrolled = true
	if s.enrollment != nil && !sameEnrollmentIdentity(*s.enrollment, s.binding) {
		state.Enrolled = false
	}
	if mainErr == nil && recoveryErr == nil {
		state.ServicesMatch = serviceConfigMatches(main, image, "--service", true) && serviceConfigMatches(recovery, image, "--recover-service", false)
		return state, nil
	}
	if !errors.Is(mainErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) || !errors.Is(recoveryErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return state, errors.New("unknown or partially installed SCM state")
	}
	if err = verifyRetiredInstallation(files, s.binding); err != nil {
		return state, err
	}
	state.Retired = true
	if s.enrollment != nil {
		_, err = retiredEnrollmentTarget(s.binding, *s.enrollment)
		state.ReenrollmentAllowed = err == nil
	}
	s.retired = true
	return state, nil
}
func (s *windowsInstallSystem) Enrollment() (Binding, error) {
	if s.enrollment == nil {
		return Binding{}, errors.New("ordinary enrollment unavailable")
	}
	return *s.enrollment, nil
}
func protectedInstallDirectory(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return checkProtectedACL(path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(path)
	for current := parent; ; current = filepath.Dir(current) {
		name, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return err
		}
		attrs, err := windows.GetFileAttributes(name)
		if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("installer parent is unverified or reparse")
		}
		if err = checkACLMask(current, ancestorReplaceMask); err != nil {
			return err
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	security, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: security}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	err = windows.CreateDirectory(name, &attributes)
	runtime.KeepAlive(security)
	if err != nil {
		return err
	}
	return checkProtectedACL(path)
}
func (s *windowsInstallSystem) Provision(enrollment Binding) error {
	location, err := winprofile.LocationForSID(enrollment.OwnerSID)
	if err != nil || localProfileID(location.Profile) != enrollment.ProfileID {
		return errors.New("captured desktop profile namespace differs")
	}
	if err = winprofile.Provision(enrollment.OwnerSID); err != nil {
		return err
	}
	return s.provisionJournal(enrollment)
}
func (s *windowsInstallSystem) ConfigureServices() error {
	return s.configureJournalServices()
}

func fixedService(name string) (*mgr.Mgr, *mgr.Service, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return nil, nil, err
	}
	service, err := manager.OpenService(name)
	if err != nil {
		manager.Disconnect()
		return nil, nil, err
	}
	return manager, service, nil
}
func waitService(ctx context.Context, service *mgr.Service, state svc.State) error {
	for {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == state {
			if state == svc.Stopped && (status.Win32ExitCode != 0 || status.ServiceSpecificExitCode != 0) {
				return errors.New("SCM operation failed")
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func (s *windowsInstallSystem) StartMain(ctx context.Context) error {
	manager, service, err := fixedService(ServiceName)
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	defer service.Close()
	if err = service.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	return waitService(ctx, service, svc.Running)
}
func (s *windowsInstallSystem) StopMain(ctx context.Context) error {
	s.mainDead = false
	manager, service, err := fixedService(ServiceName)
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	defer service.Close()
	before, err := service.Query()
	if err != nil {
		return err
	}
	if before.State == svc.Stopped {
		s.mainDead = true
		return nil
	}
	if before.ProcessId == 0 {
		return errors.New("main service process identity unknown")
	}
	process, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, before.ProcessId)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(process)
	if _, err = service.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return err
	}
	stopErr := waitService(ctx, service, svc.Stopped)
	for {
		state, waitErr := windows.WaitForSingleObject(process, 50)
		if waitErr != nil {
			return errors.Join(stopErr, waitErr)
		}
		if state == windows.WAIT_OBJECT_0 {
			s.mainDead = true
			return stopErr
		}
		select {
		case <-ctx.Done():
			return errors.Join(stopErr, ctx.Err())
		default:
		}
	}
}
func (s *windowsInstallSystem) MainStopped() (bool, error) {
	manager, service, err := fixedService(ServiceName)
	if err != nil {
		return false, err
	}
	defer manager.Disconnect()
	defer service.Close()
	status, err := service.Query()
	return err == nil && status.State == svc.Stopped && s.mainDead, err
}
func (s *windowsInstallSystem) RecoverExact(ctx context.Context) error {
	stopped, observeErr := s.MainStopped()
	if observeErr != nil || !stopped {
		return errors.New("main service is still running or unknown; cross-process recovery refused")
	}
	manager, service, err := fixedService(RecoveryServiceName)
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Stopped {
		if err = waitService(ctx, service, svc.Stopped); err != nil {
			return err
		}
	}
	nonce, err := newID("recover-")
	if err != nil {
		return err
	}
	if err = service.Start(nonce); err != nil {
		return err
	}
	files := installedStateFiles{root: s.root}
	for {
		data, readErr := files.Read("recovery-ack.json")
		if readErr == nil {
			var acknowledgement recoveryAcknowledgement
			if decodeState(data, &acknowledgement) == nil && acknowledgement.Version == 1 && acknowledgement.Nonce == nonce && acknowledgement.ProfileID == s.control.ProfileID && acknowledgement.Clean {
				bindingData, err := files.Read(filepath.Join("bindings", s.control.ProfileID+".json"))
				if err != nil {
					return err
				}
				var binding Binding
				if decodeState(bindingData, &binding) != nil || binding.RunRef != "" || binding.LastRestorationID != acknowledgement.RestorationID {
					return errors.New("recovery acknowledgement has no matching publication")
				}
				receipt, err := readRestoration(files, binding.LastRestorationID)
				if err != nil || !sameEnrollment(receipt.Enrollment, binding) {
					return errors.New("recovery acknowledgement lacks strict proof")
				}
				if err = waitService(ctx, service, svc.Stopped); err != nil {
					return err
				}
				s.binding = binding
				s.recoveryNonce = nonce
				return nil
			}
		}
		if readErr != nil && !errors.Is(readErr, errProtectedStateMissing) {
			return readErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func (s *windowsInstallSystem) DeleteServices() error {
	return s.deleteJournalServices()
}
