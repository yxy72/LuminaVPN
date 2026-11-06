//go:build windows

package winservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// Exclusive object lifetime, not thread-owned mutex acquisition: Go goroutines
// may move OS threads. Another installer/recovery command must not join or steal
// an existing object, including an object precreated by an untrusted process.
func acquireInstallerLock() (windows.Handle, error) {
	security, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return 0, err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: security}
	name, err := windows.UTF16PtrFromString(`Global\LuminaVPNInstallerTransaction`)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateMutex(&attributes, false, name)
	runtime.KeepAlive(security)
	if err != nil {
		if handle != 0 {
			windows.CloseHandle(handle)
		}
		return 0, errors.New("another or unknown installer transaction is present")
	}
	if err = verifyInstallerLock(handle); err != nil {
		windows.CloseHandle(handle)
		return 0, err
	}
	return handle, nil
}

func verifyInstallerLock(handle windows.Handle) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || owner.String() != "S-1-5-18" && owner.String() != "S-1-5-32-544" {
		return errors.New("installer lock has an untrusted owner")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 2 {
		return errors.New("installer lock has an unknown DACL")
	}
	seen := map[string]bool{}
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var raw *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(acl, index, &raw); err != nil {
			return err
		}
		if raw.Header.AceType != 0 || raw.Header.AceFlags != 0 {
			return errors.New("installer lock has an unknown ACE")
		}
		sid := (*windows.SID)(unsafe.Pointer(&raw.SidStart)).String()
		if sid != "S-1-5-18" && sid != "S-1-5-32-544" || seen[sid] || uint32(raw.Mask) != windows.GENERIC_ALL && uint32(raw.Mask) != 0x1f0001 {
			return errors.New("installer lock access differs from its fixed principals")
		}
		seen[sid] = true
	}
	runtime.KeepAlive(sd)
	return nil
}

func (s *windowsInstallSystem) journalIdentity() (string, string, error) {
	image, err := s.installation.Executable(ServiceImage)
	if err != nil {
		return "", "", err
	}
	data, err := json.Marshal(struct {
		Root, Release string
		Images        map[ExecutableKind]string
		Pins          map[ExecutableKind]FilePin
		Runtime       any
	}{s.installation.root, s.installation.release, s.installation.images, s.installation.pins, s.installation.runtimeManifest})
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(data)
	return image, hex.EncodeToString(sum[:]), nil
}

func (s *windowsInstallSystem) installerContext() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

func (s *windowsInstallSystem) prepareJournalTree() error {
	for _, directory := range []string{filepath.Dir(s.root), s.root, filepath.Join(s.root, "bindings"), filepath.Join(s.root, "operations"), filepath.Join(s.root, "runs")} {
		if err := protectedInstallDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func (s *windowsInstallSystem) inspectInstallerJournal(files protectedStateFiles, manager *mgr.Mgr) (BootstrapState, bool, error) {
	state := BootstrapState{Present: true}
	j, exists, err := readInstallJournal(files)
	if err != nil {
		return state, true, err
	}
	if !exists {
		return state, false, nil
	}
	image, digest, err := s.journalIdentity()
	if err != nil {
		return state, true, err
	}
	if j.Phase == "complete" && !(j.Action == "retire" && s.command == CommandUninstall && j.Image == image && j.ReleaseDigest == digest) {
		return state, false, nil
	}
	if j.Image != image || j.ReleaseDigest != digest {
		return state, true, errors.New("pending installer release identity changed")
	}
	native := &journalSCM{manager: manager, image: image, ctx: s.installerContext(), allowRunning: j.Published != nil}
	if j.Action == "bootstrap" {
		recovering := installerJournalRecoveryAllowed(j, s.command)
		if !recovering && (s.command != CommandBootstrap || s.enrollment == nil || !journalCallerMatches(j, *s.enrollment)) {
			return state, true, errors.New("only the original verified installer login may resume")
		}
		if _, _, err = inspectJournalEnrollment(files, j); err != nil {
			return state, true, err
		}
		for _, name := range []string{ServiceName, RecoveryServiceName} {
			if err = native.inspectPending(name, j.Phase == "prepared", j.Phase == "prepared", false); err != nil {
				return state, true, err
			}
		}
		if j.Phase == "prepared" {
			if err = native.inspectPreparedPair(); err != nil {
				return state, true, err
			}
		}
		if recovering {
			s.control, s.binding, err = provisionedInstallerRecovery(files, j)
			if err != nil {
				return state, true, err
			}
			mainSID, _, _, mainErr := windows.LookupSID("", "NT SERVICE\\"+ServiceName)
			recoverySID, _, _, recoveryErr := windows.LookupSID("", "NT SERVICE\\"+RecoveryServiceName)
			if mainErr != nil || recoveryErr != nil || mainSID == nil || recoverySID == nil || s.control.ServiceSID != mainSID.String() || s.control.RecoveryServiceSID != recoverySID.String() {
				return state, true, errors.New("provisioned recovery service identity changed")
			}
			state.ServicesMatch = true
		} else {
			state.BootstrapPending = true
		}
		state.Trusted, state.Enrolled = true, true
	} else {
		if s.command != CommandUninstall {
			return state, true, errors.New("pending strict retirement requires the fixed uninstall entry")
		}
		if err = verifyJournalRetirement(files, j); err != nil {
			return state, true, err
		}
		for _, name := range []string{ServiceName, RecoveryServiceName} {
			deleted := j.Phase == "complete" || j.Phase == "recovery_deleted" || name == ServiceName && j.Phase == "main_deleted"
			if err = native.inspectPending(name, true, false, deleted); err != nil {
				return state, true, err
			}
		}
		s.binding = j.Target
		state.Trusted, state.Enrolled, state.ServicesMatch, state.UninstallPending = true, true, true, true
	}
	s.journal = &j
	return state, true, nil
}

func (s *windowsInstallSystem) configureJournalServices() error {
	if s.installerLock == 0 || s.enrollment == nil {
		return errors.New("exclusive verified installer context required")
	}
	if err := s.prepareJournalTree(); err != nil {
		return err
	}
	image, digest, err := s.journalIdentity()
	if err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	files := installedStateFiles{root: s.root}
	if s.journal == nil {
		native := &journalSCM{manager: manager, image: image, ctx: s.installerContext()}
		for _, name := range []string{ServiceName, RecoveryServiceName} {
			if err = native.Absent(name); err != nil {
				return err
			}
		}
		target := *s.enrollment
		var previous *Binding
		if s.retired {
			if err = verifyRetiredInstallation(files, s.binding); err != nil {
				return err
			}
			target, err = retiredEnrollmentTarget(s.binding, target)
			if err != nil {
				return err
			}
			prior := s.binding
			previous = &prior
		} else {
			target.ServiceInstance, err = newID("service-")
			if err != nil {
				return err
			}
		}
		j := installJournal{Version: 1, Action: "bootstrap", Phase: "prepared", ReleaseDigest: digest, Image: image, Previous: previous, Target: target}
		if err = beginInstallJournal(files, j); err != nil {
			return err
		}
		s.journal = &j
	}
	j := *s.journal
	if j.Action != "bootstrap" || j.Image != image || j.ReleaseDigest != digest || !journalCallerMatches(j, *s.enrollment) {
		return errors.New("installer journal no longer matches the verified release/login")
	}
	native := &journalSCM{manager: manager, image: image, ctx: s.installerContext(), allowRunning: j.Published != nil}
	if j.Phase == "prepared" {
		if err = native.inspectPreparedPair(); err != nil {
			return err
		}
	}
	next, err := resumeBootstrapServices(files, j, native)
	if err != nil {
		return err
	}
	s.journal = &next
	return nil
}

func (s *windowsInstallSystem) provisionJournal(captured Binding) error {
	if s.installerLock == 0 || s.journal == nil || s.journal.Action != "bootstrap" || !journalCallerMatches(*s.journal, captured) {
		return errors.New("frozen installer enrollment required")
	}
	files := installedStateFiles{root: s.root}
	j, exists, err := readInstallJournal(files)
	if err != nil || !exists || !sameInstallJournalPlan(j, *s.journal) || j.Phase != s.journal.Phase || j.Phase != "services_ready" && j.Phase != "provisioned" {
		return errors.New("installer provisioning phase changed")
	}
	enrollment, err := publishJournalEnrollment(files, j)
	if err != nil {
		return err
	}
	main, _, _, err := windows.LookupSID("", "NT SERVICE\\"+ServiceName)
	if err != nil {
		return err
	}
	recovery, _, _, err := windows.LookupSID("", "NT SERVICE\\"+RecoveryServiceName)
	if err != nil {
		return err
	}
	control := machineControl{Version: 1, AllowedOwnerSID: enrollment.OwnerSID, AllowedLogonSID: enrollment.LogonSID, AuthenticationID: enrollment.AuthenticationID, SessionID: enrollment.SessionID, ProfileID: enrollment.ProfileID, ServiceInstance: enrollment.ServiceInstance, ServiceSID: main.String(), RecoveryServiceSID: recovery.String(), ValidationOnly: platform.WindowsClientValidationOnly, LogonEpoch: enrollment.LogonEpoch}
	data, readErr := files.Read("machine-control.json")
	if readErr == nil {
		var prior machineControl
		if decodeState(data, &prior) != nil {
			return errors.New("unknown installer control publication")
		}
		binding, err := prior.binding()
		if err != nil || !samePermanentEnrollment(binding, j.Target) || prior.ServiceSID != main.String() || prior.RecoveryServiceSID != recovery.String() || (j.Previous == nil || j.Published != nil) && prior != control {
			return errors.New("installer control belongs to another publication")
		}
	} else if !errors.Is(readErr, errProtectedStateMissing) || j.Previous != nil || j.Published != nil {
		return errors.New("installer control publication is missing or unknown")
	}
	if j.Published == nil {
		data, err = json.Marshal(control)
		if err != nil {
			return err
		}
		if err = files.Write("machine-control.json", data); err != nil {
			return err
		}
		j.Published = &enrollment
		j.Phase = "provisioned"
		if err = writeInstallJournal(files, j); err != nil {
			return err
		}
	}
	s.control, s.binding, s.journal = control, enrollment, &j
	return nil
}

func (s *windowsInstallSystem) CommitBootstrap() error {
	if s.installerLock == 0 || s.journal == nil || s.journal.Published == nil || s.journal.Phase != "provisioned" {
		return errors.New("installer completion has no durable provisioning")
	}
	j := *s.journal
	j.Phase = "complete"
	if err := writeInstallJournal(installedStateFiles{root: s.root}, j); err != nil {
		return err
	}
	s.journal = &j
	return nil
}

func (s *windowsInstallSystem) deleteJournalServices() error {
	if s.installerLock == 0 {
		return errors.New("exclusive installer context required")
	}
	image, digest, err := s.journalIdentity()
	if err != nil {
		return err
	}
	files := installedStateFiles{root: s.root}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	native := &journalSCM{manager: manager, image: image, ctx: s.installerContext()}
	if s.journal == nil {
		if s.recoveryNonce == "" {
			return errors.New("strict recovery acknowledgement required before retirement")
		}
		j := installJournal{Version: 1, Action: "retire", Phase: "prepared", ReleaseDigest: digest, Image: image, Target: s.binding}
		if err = verifyJournalRetirement(files, j); err != nil {
			return err
		}
		for _, name := range []string{ServiceName, RecoveryServiceName} {
			if err = native.Verify(name); err != nil {
				return err
			}
		}
		if err = beginInstallJournal(files, j); err != nil {
			return err
		}
		s.journal = &j
	}
	j := *s.journal
	if j.Action != "retire" || j.Image != image || j.ReleaseDigest != digest {
		return errors.New("retirement journal release changed")
	}
	if err = verifyJournalRetirement(files, j); err != nil {
		return err
	}
	if j.Phase == "prepared" {
		data, err := json.Marshal(retiredInstallation{Version: 1, ProfileID: j.Target.ProfileID, RestorationID: j.Target.LastRestorationID, ServiceInstance: j.Target.ServiceInstance})
		if err != nil {
			return err
		}
		if err = files.Write("installation-retired.json", data); err != nil {
			return err
		}
	} else if err = verifyRetiredInstallation(files, j.Target); err != nil {
		return err
	}
	native.beforeMutation = func() error { return verifyJournalRetirement(files, j) }
	next, err := resumeRetirementServices(files, j, native)
	if err != nil {
		return err
	}
	s.journal = &next
	return nil
}

type journalSCM struct {
	manager        *mgr.Mgr
	image          string
	ctx            context.Context
	allowRunning   bool
	beforeMutation func() error
}

func fixedJournalService(name string) (string, string, bool, error) {
	switch name {
	case ServiceName:
		return "--service", "LuminaVPN Service", true, nil
	case RecoveryServiceName:
		return "--recover-service", "LuminaVPN Recovery", false, nil
	default:
		return "", "", false, errors.New("installer service name is not fixed")
	}
}

func readJournalServicePrefix(service *mgr.Service, image, name string) (journalServicePrefix, error) {
	prefix := journalServicePrefix{Present: true}
	argument, display, automatic, err := fixedJournalService(name)
	if err != nil {
		return prefix, err
	}
	c, err := service.Config()
	if err != nil {
		return prefix, err
	}
	start := uint32(mgr.StartManual)
	if automatic {
		start = mgr.StartAutomatic
	}
	if !strings.EqualFold(c.BinaryPathName, windows.EscapeArg(image)+" "+argument) || !(strings.EqualFold(c.ServiceStartName, "LocalSystem") || c.ServiceStartName == "") || c.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || c.StartType != start || c.ErrorControl != mgr.ErrorNormal || c.LoadOrderGroup != "" || c.TagId != 0 || len(c.Dependencies) != 0 || c.DisplayName != display || c.Description != "" || c.DelayedAutoStart || c.SidType != windows.SERVICE_SID_TYPE_UNRESTRICTED && c.SidType != windows.SERVICE_SID_TYPE_NONE {
		return prefix, errors.New("fixed installer service configuration changed")
	}
	prefix.SID = c.SidType == windows.SERVICE_SID_TYPE_UNRESTRICTED
	command, err := service.RecoveryCommand()
	if err != nil {
		return prefix, err
	}
	actions, err := service.RecoveryActions()
	if err != nil {
		return prefix, err
	}
	period, err := service.ResetPeriod()
	if err != nil {
		return prefix, err
	}
	flag, err := service.RecoveryActionsOnNonCrashFailures()
	if err != nil {
		return prefix, err
	}
	prefix.NonCrash = flag
	reboot, err := service.RebootMessage()
	if err != nil || reboot != "" {
		return prefix, errors.New("unknown installer service reboot action")
	}
	if automatic {
		want := windows.EscapeArg(image) + " --recover"
		if command != "" && command != want {
			return prefix, errors.New("main service recovery command changed")
		}
		prefix.Command = command == want
		if len(actions) == 1 && actions[0].Type == mgr.RunCommand && actions[0].Delay == time.Second && period == 86400 {
			prefix.Actions = true
		} else if len(actions) != 0 || period != 0 {
			return prefix, errors.New("main service recovery actions changed")
		}
	} else if command != "" || len(actions) != 0 || period != 0 || flag {
		return prefix, errors.New("recovery service failure actions changed")
	}
	return prefix, nil
}

func knownJournalServiceConfig(service *mgr.Service, image, name string, partial bool) error {
	prefix, err := readJournalServicePrefix(service, image, name)
	if err != nil {
		return err
	}
	return validateJournalServicePrefix(name, prefix, partial)
}

func (n *journalSCM) inspectPreparedPair() error {
	prefixes := []journalServicePrefix{{}, {}}
	for index, name := range []string{ServiceName, RecoveryServiceName} {
		service, err := n.manager.OpenService(name)
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			continue
		}
		if err != nil {
			return err
		}
		prefixes[index], err = readJournalServicePrefix(service, n.image, name)
		service.Close()
		if err != nil {
			return err
		}
	}
	return validatePreparedServicePrefixes(prefixes[0], prefixes[1])
}

func (n *journalSCM) inspectPending(name string, allowAbsent, partial, deleted bool) error {
	if _, _, _, err := fixedJournalService(name); err != nil {
		return err
	}
	service, err := n.manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) && (allowAbsent || deleted) {
		return nil
	}
	if err != nil {
		return err
	}
	defer service.Close()
	if deleted {
		return errors.New("retired journal service reappeared")
	}
	if err = knownJournalServiceConfig(service, n.image, name, partial); err != nil {
		return err
	}
	status, err := service.Query()
	if err != nil || status.State != svc.Stopped && !(n.allowRunning && name == ServiceName && status.State == svc.Running) {
		return errors.New("installer service is running or unknown before provisioning")
	}
	return nil
}

func (n *journalSCM) Ensure(name string, partial bool) error {
	argument, display, automatic, err := fixedJournalService(name)
	if err != nil {
		return err
	}
	service, err := n.manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		start := uint32(mgr.StartManual)
		if automatic {
			start = mgr.StartAutomatic
		}
		service, err = n.manager.CreateService(name, n.image, mgr.Config{DisplayName: display, ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, StartType: start, ErrorControl: mgr.ErrorNormal, ServiceStartName: "LocalSystem", SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}, argument)
	}
	if err != nil {
		return err
	}
	defer service.Close()
	if err = knownJournalServiceConfig(service, n.image, name, partial); err != nil {
		return err
	}
	status, err := service.Query()
	if err != nil || status.State != svc.Stopped {
		return errors.New("pending installer service is not stopped")
	}
	c, err := service.Config()
	if err != nil {
		return err
	}
	if c.SidType == windows.SERVICE_SID_TYPE_NONE {
		info := uint32(windows.SERVICE_SID_TYPE_UNRESTRICTED)
		if err = windows.ChangeServiceConfig2(service.Handle, windows.SERVICE_CONFIG_SERVICE_SID_INFO, (*byte)(unsafe.Pointer(&info))); err != nil {
			return err
		}
	}
	if automatic {
		if err = service.SetRecoveryCommand(windows.EscapeArg(n.image) + " --recover"); err != nil {
			return err
		}
		if err = service.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.RunCommand, Delay: time.Second}}, 86400); err != nil {
			return err
		}
		if err = service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
			return err
		}
	}
	return knownJournalServiceConfig(service, n.image, name, false)
}

func (n *journalSCM) Verify(name string) error {
	return n.inspectPending(name, false, false, false)
}

var errInstallerServicePresent = errors.New("fixed installer service is still present")

func (n *journalSCM) Absent(name string) error {
	if _, _, _, err := fixedJournalService(name); err != nil {
		return err
	}
	service, err := n.manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	service.Close()
	return errInstallerServicePresent
}

func (n *journalSCM) Remove(name string) error {
	if n.beforeMutation != nil {
		if err := n.beforeMutation(); err != nil {
			return err
		}
	}
	if _, _, _, err := fixedJournalService(name); err != nil {
		return err
	}
	service, err := n.manager.OpenService(name)
	if err == nil {
		if err = knownJournalServiceConfig(service, n.image, name, false); err == nil {
			status, queryErr := service.Query()
			if queryErr != nil || status.State != svc.Stopped {
				err = errors.New("running or unknown service cannot be retired")
			}
		}
		if err == nil {
			err = service.Delete()
		}
		service.Close()
	}
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return err
	}
	ctx := n.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		err = n.Absent(name)
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) && !errors.Is(err, errInstallerServicePresent) {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.New("SCM deletion absence was not confirmed; journal retained")
		case <-time.After(50 * time.Millisecond):
		}
	}
}
