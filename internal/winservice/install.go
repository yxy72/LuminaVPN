package winservice

import (
	"context"
	"errors"
)

const RecoveryServiceName = "LuminaVPNRecoveryService"

func installerAdministrator(sid string, elevated, enabledAdmin, denyOnly bool) bool {
	return sid == "S-1-5-18" || (elevated && enabledAdmin && !denyOnly)
}

type Command string

const (
	CommandService         Command = "--service"
	CommandBootstrap       Command = "--bootstrap"
	CommandRecoverService  Command = "--recover-service"
	CommandUninstall       Command = "--uninstall"
	CommandRecover         Command = "--recover"
	CommandPrintPlan       Command = "--print-install-plan"
	CommandResumePreflight Command = "--resume-install-preflight"
)

func ParseCommand(args []string) (Command, error) {
	if len(args) != 1 {
		return "", errors.New("one fixed service entry required")
	}
	command := Command(args[0])
	switch command {
	case CommandService, CommandBootstrap, CommandRecoverService, CommandUninstall, CommandRecover, CommandPrintPlan, CommandResumePreflight:
		return command, nil
	}
	return "", errors.New("unsupported service entry")
}

// EnrollmentFacts are obtained from held OS token/process handles, never
// decoded from command-line/IPC claims. Full and limited token AuthIDs may
// differ in split-token mode; that branch persists the limited desktop identity.
// Unfiltered administrators retain their actual elevated desktop identity.
type EnrollmentFacts struct {
	SID, LogonSID, AuthenticationID       string
	SessionID                             uint32
	TokenType, ImpersonationLevel         uint32
	ElevationType                         uint32
	Elevated, EnabledAdmin, AdminDenyOnly bool
	LogonEpoch                            string
	Interactive                           bool
	ProfileID                             string
}

func verifiedEnrollment(full, linked, shell EnrollmentFacts) (Binding, error) {
	if !validInteractiveIdentity(full) || full.TokenType != 1 || !full.Elevated || !full.EnabledAdmin || full.AdminDenyOnly || shell.TokenType != 1 {
		return Binding{}, errors.New("interactive installer enrollment could not be independently verified")
	}
	user := linked
	switch full.ElevationType {
	case tokenElevationFull:
		// A split-token installer enrolls its actual limited desktop identity,
		// whose authentication ID may differ from the elevated installer.
		if linked.TokenType != 1 || linked.ElevationType != tokenElevationLimited || shell.ElevationType != tokenElevationLimited || desktopTokenMode(linked) != desktopStandard || desktopTokenMode(shell) != desktopStandard || !sameDesktopLogin(linked, shell) || full.SID != linked.SID || full.SessionID != linked.SessionID || full.ProfileID != linked.ProfileID {
			return Binding{}, errors.New("linked desktop identity differs from installer enrollment")
		}
	case tokenElevationDefault:
		// UAC-disabled / unfiltered administrators have no linked token. This
		// explicit mode keeps their real elevation and requires the installer's
		// entire OS login tuple to match the independently opened desktop shell.
		if linked != (EnrollmentFacts{}) || desktopTokenMode(full) != desktopUnfilteredAdmin || desktopTokenMode(shell) != desktopUnfilteredAdmin || !sameDesktopLogin(full, shell) {
			return Binding{}, errors.New("unfiltered administrator differs from desktop enrollment")
		}
		user = full
	default:
		return Binding{}, errors.New("unsupported installer token mode")
	}
	return Binding{ProfileID: user.ProfileID, OwnerSID: user.SID, LogonSID: user.LogonSID, AuthenticationID: user.AuthenticationID, SessionID: user.SessionID, ExecutorSID: "S-1-5-18", Revision: 1, LogonEpoch: user.LogonEpoch}, nil
}

type BootstrapState struct {
	Present, Trusted, Enrolled, ServicesMatch, Retired bool
	// ReenrollmentAllowed is set only after strict installation retirement and
	// a newly captured desktop login's stable owner/profile have been verified.
	// It never permits replacing an existing, nonretired service enrollment.
	ReenrollmentAllowed bool
	// Pending flags require the protected journal's frozen plan and current OS
	// observations. They never describe an arbitrary partial SCM installation.
	BootstrapPending, UninstallPending bool
}

type retiredInstallation struct {
	Version         int    `json:"version"`
	ProfileID       string `json:"profile_id"`
	RestorationID   string `json:"restoration_id"`
	ServiceInstance string `json:"service_instance"`
}

func verifyRetiredInstallation(files protectedStateFiles, binding Binding) error {
	data, err := files.Read("installation-retired.json")
	if err != nil {
		return errors.New("SCM absent without strict retirement publication")
	}
	var retired retiredInstallation
	if decodeState(data, &retired) != nil || retired.Version != 1 || retired.ProfileID != binding.ProfileID || retired.ServiceInstance != binding.ServiceInstance || retired.RestorationID != binding.LastRestorationID || binding.RunRef != "" || binding.PendingEnrollmentID != "" || !validOwnedBinding(binding, binding) {
		return errors.New("invalid retired enrollment")
	}
	receipt, err := readRestoration(files, retired.RestorationID)
	if err != nil || !sameEnrollment(receipt.Enrollment, binding) {
		return errors.New("retirement has no strict restoration receipt")
	}
	return nil
}

func sameEnrollmentIdentity(a, b Binding) bool {
	return a.ProfileID == b.ProfileID && a.OwnerSID == b.OwnerSID && a.LogonSID == b.LogonSID && a.AuthenticationID == b.AuthenticationID && a.SessionID == b.SessionID && a.ExecutorSID == b.ExecutorSID && a.LogonEpoch == b.LogonEpoch
}

// retiredEnrollmentTarget copies only the independently observed login tuple.
// Permanent ownership and the service instance stay bound to the retired tree.
func retiredEnrollmentTarget(previous, captured Binding) (Binding, error) {
	if previous.ProfileID != captured.ProfileID || previous.OwnerSID != captured.OwnerSID || previous.ExecutorSID != captured.ExecutorSID || captured.LogonEpoch == "" || previous.Revision == ^uint64(0) {
		return Binding{}, errors.New("retired installation belongs to another owner or profile")
	}
	target := previous
	target.LogonSID, target.AuthenticationID = captured.LogonSID, captured.AuthenticationID
	target.SessionID, target.LogonEpoch = captured.SessionID, captured.LogonEpoch
	target.Revision++
	if !validOwnedBinding(target, previous) || target.RunRef != "" || target.PendingEnrollmentID != "" {
		return Binding{}, errors.New("desktop retired enrollment unavailable")
	}
	return target, nil
}

// provisionRetiredEnrollment uses the existing durable rotation publication:
// a new login gets a new receipt tied to the old exact restoration evidence,
// rather than inheriting a receipt whose enrollment still names the old login.
func provisionRetiredEnrollment(files protectedStateFiles, previous, captured Binding) (Binding, error) {
	if err := verifyRetiredInstallation(files, previous); err != nil {
		return Binding{}, err
	}
	target, err := retiredEnrollmentTarget(previous, captured)
	if err != nil {
		return Binding{}, err
	}
	owners, err := newFileOwnershipStore(files, previous)
	if err != nil {
		return Binding{}, err
	}
	if sameEnrollment(previous, target) {
		if err = owners.Save(target); err != nil {
			return Binding{}, err
		}
		return target, nil
	}
	return owners.Rotate(previous, target)
}

type InstallSystem interface {
	Inspect() (BootstrapState, error)
	Enrollment() (Binding, error)
	Provision(Binding) error
	ConfigureServices() error
	StartMain(context.Context) error
	StopMain(context.Context) error
	MainStopped() (bool, error)
	RecoverExact(context.Context) error
	DeleteServices() error
}
type InstallResult struct {
	Completed    bool   `json:"completed"`
	Action       string `json:"action"`
	Restored     bool   `json:"restored"`
	FilesDeleted bool   `json:"files_deleted"`
}

func Bootstrap(ctx context.Context, system InstallSystem) (InstallResult, error) {
	result := InstallResult{Action: "bootstrap"}
	state, err := system.Inspect()
	if err != nil {
		return result, err
	}
	if state.Present {
		if state.BootstrapPending {
			if !state.Trusted || !state.Enrolled {
				return result, errors.New("pending installer enrollment is unknown")
			}
		} else {
			if !state.Trusted || (!state.Enrolled && !(state.Retired && state.ReenrollmentAllowed)) || (!state.ServicesMatch && !state.Retired) {
				return result, errors.New("existing installation is unknown; no state was replaced")
			}
			if !state.Retired {
				if err = system.StartMain(ctx); err != nil {
					return result, err
				}
				result.Completed = true
				return result, nil
			}
		}
	}
	enrollment, err := system.Enrollment()
	if err != nil {
		return result, err
	}
	if err = system.ConfigureServices(); err != nil {
		return result, err
	}
	if err = system.Provision(enrollment); err != nil {
		return result, err
	}
	if err = system.StartMain(ctx); err != nil {
		return result, err
	}
	if commit, ok := system.(interface{ CommitBootstrap() error }); ok {
		if err = commit.CommitBootstrap(); err != nil {
			return result, err
		}
	}
	result.Completed = true
	return result, nil
}
func Uninstall(ctx context.Context, system InstallSystem) (InstallResult, error) {
	result := InstallResult{Action: "uninstall"}
	state, err := system.Inspect()
	if err != nil {
		return result, err
	}
	if !state.Present || !state.Trusted || !state.Enrolled || !state.ServicesMatch {
		return result, errors.New("known installed enrollment required")
	}
	if state.UninstallPending {
		// The journal was written only after exact recovery and is rechecked
		// before every remaining fixed SCM deletion. Never repeat unknown recovery.
		result.Restored = true
		if err = system.DeleteServices(); err != nil {
			return result, err
		}
		result.Completed = true
		return result, nil
	}
	// Stopping may itself run restoration. A distinct SYSTEM recovery service
	// still must produce this request's exact acknowledgement before deletion.
	_ = system.StopMain(ctx)
	stopped, observeErr := system.MainStopped()
	if observeErr != nil || !stopped {
		return result, errors.New("main service quiescence was not proved")
	}
	if err = system.RecoverExact(ctx); err != nil {
		return result, err
	}
	result.Restored = true
	if err = system.DeleteServices(); err != nil {
		return result, err
	}
	result.Completed = true
	// Installer-owned release deletion is a later step, gated by this result.
	// Recovery journals and historical run directories are always preserved.
	return result, nil
}
