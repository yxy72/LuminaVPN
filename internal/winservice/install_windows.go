//go:build windows

package winservice

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"netlaunch/internal/platform"
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
}
type retiredInstallation struct {
	Version         int    `json:"version"`
	ProfileID       string `json:"profile_id"`
	RestorationID   string `json:"restoration_id"`
	ServiceInstance string `json:"service_instance"`
}

func newWindowsInstallSystem(command Command) (*windowsInstallSystem, error) {
	if err := ValidateInstallerImage(); err != nil {
		return nil, err
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	enabledAdmin, denyOnly := false, false
	if user.User.Sid.String() != "S-1-5-18" {
		groups, groupErr := token.GetTokenGroups()
		if groupErr != nil {
			return nil, groupErr
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
			return nil, err
		}
	}
	if !installerAdministrator(user.User.Sid.String(), elevated, enabledAdmin, denyOnly) {
		return nil, errors.New("reviewed elevated installer context required")
	}
	installation, err := LoadInstallation()
	if err != nil {
		return nil, err
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return nil, err
	}
	system := &windowsInstallSystem{installation: installation, root: filepath.Join(base, "LuminaVPN", "ServiceState")}
	if command == CommandBootstrap {
		binding, err := captureInstallerEnrollment()
		if err != nil {
			return nil, err
		}
		system.enrollment = &binding
	}
	return system, nil
}
func RunInstallerCommand(ctx context.Context, command Command) (InstallResult, error) {
	if command != CommandBootstrap && command != CommandUninstall && command != CommandRecover {
		return InstallResult{}, errors.New("fixed administrative entry required")
	}
	system, err := newWindowsInstallSystem(command)
	if err != nil {
		return InstallResult{}, err
	}
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
	config, err := service.Config()
	if err != nil {
		return false
	}
	expected := windows.EscapeArg(image) + " " + argument
	start := uint32(mgr.StartManual)
	if automatic {
		start = mgr.StartAutomatic
	}
	return strings.EqualFold(config.BinaryPathName, expected) && (strings.EqualFold(config.ServiceStartName, "LocalSystem") || config.ServiceStartName == "") && config.ServiceType == windows.SERVICE_WIN32_OWN_PROCESS && config.StartType == start && config.SidType == windows.SERVICE_SID_TYPE_UNRESTRICTED
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
	if s.enrollment != nil && (s.enrollment.ProfileID != s.binding.ProfileID || s.enrollment.OwnerSID != s.binding.OwnerSID || s.enrollment.LogonSID != s.binding.LogonSID || s.enrollment.AuthenticationID != s.binding.AuthenticationID || s.enrollment.SessionID != s.binding.SessionID) {
		state.Enrolled = false
	}
	if mainErr == nil && recoveryErr == nil {
		state.ServicesMatch = serviceConfigMatches(main, image, "--service", true) && serviceConfigMatches(recovery, image, "--recover-service", false)
		return state, nil
	}
	if !errors.Is(mainErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) || !errors.Is(recoveryErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return state, errors.New("unknown or partially installed SCM state")
	}
	data, err = files.Read("installation-retired.json")
	if err != nil {
		return state, errors.New("SCM absent without strict retirement publication")
	}
	var retired retiredInstallation
	if decodeState(data, &retired) != nil || retired.Version != 1 || retired.ProfileID != s.binding.ProfileID || retired.ServiceInstance != s.binding.ServiceInstance || retired.RestorationID != s.binding.LastRestorationID || s.binding.RunRef != "" {
		return state, errors.New("invalid retired enrollment")
	}
	receipt, err := readRestoration(files, retired.RestorationID)
	if err != nil || !sameEnrollment(receipt.Enrollment, s.binding) {
		return state, errors.New("retirement has no strict restoration receipt")
	}
	state.Retired = true
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
	if err := protectedInstallDirectory(filepath.Dir(s.root)); err != nil {
		return err
	}
	if err := protectedInstallDirectory(s.root); err != nil {
		return err
	}
	for _, directory := range []string{"bindings", "operations", "runs"} {
		if err := protectedInstallDirectory(filepath.Join(s.root, directory)); err != nil {
			return err
		}
	}
	main, _, _, err := windows.LookupSID("", "NT SERVICE\\"+ServiceName)
	if err != nil {
		return err
	}
	recovery, _, _, err := windows.LookupSID("", "NT SERVICE\\"+RecoveryServiceName)
	if err != nil {
		return err
	}
	instance, err := newID("service-")
	if err != nil {
		return err
	}
	if s.retired {
		instance = s.control.ServiceInstance
		enrollment.Revision = s.binding.Revision + 1
		enrollment.LastRestorationID = s.binding.LastRestorationID
	}
	enrollment.ServiceInstance = instance
	control := machineControl{Version: 1, AllowedOwnerSID: enrollment.OwnerSID, AllowedLogonSID: enrollment.LogonSID, AuthenticationID: enrollment.AuthenticationID, SessionID: enrollment.SessionID, ProfileID: enrollment.ProfileID, ServiceInstance: instance, ServiceSID: main.String(), RecoveryServiceSID: recovery.String(), ValidationOnly: platform.WindowsClientValidationOnly, LogonEpoch: enrollment.LogonEpoch}
	files := installedStateFiles{root: s.root}
	data, _ := json.Marshal(control)
	if err = files.Write("machine-control.json", data); err != nil {
		return err
	}
	data, _ = json.Marshal(enrollment)
	if err = files.Write(filepath.Join("bindings", enrollment.ProfileID+".json"), data); err != nil {
		return err
	}
	s.control, s.binding = control, enrollment
	return nil
}
func (s *windowsInstallSystem) ConfigureServices() error {
	image, err := s.installation.Executable(ServiceImage)
	if err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	main, err := manager.CreateService(ServiceName, image, mgr.Config{DisplayName: "LuminaVPN Service", ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, StartType: mgr.StartAutomatic, ErrorControl: mgr.ErrorNormal, ServiceStartName: "LocalSystem", SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}, "--service")
	if err != nil {
		return err
	}
	defer main.Close()
	recovery, err := manager.CreateService(RecoveryServiceName, image, mgr.Config{DisplayName: "LuminaVPN Recovery", ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, StartType: mgr.StartManual, ErrorControl: mgr.ErrorNormal, ServiceStartName: "LocalSystem", SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}, "--recover-service")
	if err != nil {
		return err
	}
	defer recovery.Close()
	if err = main.SetRecoveryCommand(windows.EscapeArg(image) + " --recover"); err != nil {
		return err
	}
	if err = main.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.RunCommand, Delay: time.Second}}, 86400); err != nil {
		return err
	}
	return main.SetRecoveryActionsOnNonCrashFailures(true)
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
	if s.recoveryNonce == "" || s.binding.RunRef != "" || s.binding.LastRestorationID == "" {
		return errors.New("strict recovery acknowledgement required before deletion")
	}
	files := installedStateFiles{root: s.root}
	data, _ := json.Marshal(retiredInstallation{Version: 1, ProfileID: s.binding.ProfileID, RestorationID: s.binding.LastRestorationID, ServiceInstance: s.binding.ServiceInstance})
	if err := files.Write("installation-retired.json", data); err != nil {
		return err
	}
	for _, name := range []string{ServiceName, RecoveryServiceName} {
		manager, service, err := fixedService(name)
		if err != nil {
			return err
		}
		status, err := service.Query()
		if err == nil && status.State != svc.Stopped {
			err = errors.New("running service cannot be deleted")
		}
		if err == nil {
			err = service.Delete()
		}
		service.Close()
		manager.Disconnect()
		if err != nil {
			return err
		}
	}
	return nil
}
