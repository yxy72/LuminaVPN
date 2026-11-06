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
	CommandService        Command = "--service"
	CommandBootstrap      Command = "--bootstrap"
	CommandRecoverService Command = "--recover-service"
	CommandUninstall      Command = "--uninstall"
	CommandRecover        Command = "--recover"
	CommandPrintPlan      Command = "--print-install-plan"
)

func ParseCommand(args []string) (Command, error) {
	if len(args) != 1 {
		return "", errors.New("one fixed service entry required")
	}
	command := Command(args[0])
	switch command {
	case CommandService, CommandBootstrap, CommandRecoverService, CommandUninstall, CommandRecover, CommandPrintPlan:
		return command, nil
	}
	return "", errors.New("unsupported service entry")
}

// EnrollmentFacts are obtained from held OS token/process handles, never
// decoded from command-line/IPC claims. Full and limited token AuthIDs may
// differ; only the actual limited interactive identity is persisted.
type EnrollmentFacts struct {
	SID, LogonSID, AuthenticationID string
	SessionID                       uint32
	Primary, Elevated, Limited      bool
	LogonEpoch                      string
	Interactive                     bool
}

func verifiedEnrollment(full, linked, shell EnrollmentFacts, profileID string) (Binding, error) {
	if !full.Primary || !full.Elevated || full.Limited || !linked.Primary || linked.Elevated || !linked.Limited || !linked.Interactive || !shell.Interactive || linked.LogonEpoch == "" || linked.LogonEpoch != shell.LogonEpoch || !shell.Primary || shell.Elevated || linked.SID == "S-1-5-18" || linked.SessionID == 0 || full.SID != linked.SID || full.SessionID != linked.SessionID || linked.SID != shell.SID || linked.LogonSID != shell.LogonSID || linked.AuthenticationID != shell.AuthenticationID || linked.SessionID != shell.SessionID || !sidText.MatchString(linked.SID) || !sidText.MatchString(linked.LogonSID) || linked.AuthenticationID == "" || len(linked.AuthenticationID) > 128 || !ValidProfileID(profileID) {
		return Binding{}, errors.New("ordinary interactive enrollment could not be independently verified")
	}
	return Binding{ProfileID: profileID, OwnerSID: linked.SID, LogonSID: linked.LogonSID, AuthenticationID: linked.AuthenticationID, SessionID: linked.SessionID, ExecutorSID: "S-1-5-18", Revision: 1, LogonEpoch: linked.LogonEpoch}, nil
}

type BootstrapState struct{ Present, Trusted, Enrolled, ServicesMatch, Retired bool }
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
		if !state.Trusted || !state.Enrolled || (!state.ServicesMatch && !state.Retired) {
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
