package winservice

import "errors"

// These values are a silent installer contract. NSIS forwards only this
// reserved range from its verified embedded helper.
const (
	installExitPath            = 120
	installExitImageTrust      = 121
	installExitAdministrator   = 122
	installExitLock            = 123
	installExitJournal         = 124
	installExitResumeIdentity  = 125
	installExitRelease         = 126
	installExitEnrollment      = 127
	installExitRegistry        = 128
	installExitBootstrapState  = 129
	installExitConfigureSCM    = 130
	installExitProvision       = 131
	installExitStartSCM        = 132
	installExitBootstrapCommit = 133
	installExitUninstallState  = 134
	installExitStopSCM         = 135
	installExitRecovery        = 136
	installExitDeleteSCM       = 137
	installExitResult          = 138
)

type installerFailure struct {
	code int
	err  error
}

func (e installerFailure) Error() string { return e.err.Error() }
func (e installerFailure) Unwrap() error { return e.err }

func installerFailed(code int, err error) error {
	if err == nil {
		return nil
	}
	var previous installerFailure
	if errors.As(err, &previous) {
		return err
	}
	return installerFailure{code, err}
}

func InstallerCommandExitCode(command Command, err error) int {
	if err == nil {
		return 0
	}
	switch command {
	case CommandBootstrap, CommandResumePreflight, CommandUninstall:
		var stage installerFailure
		if errors.As(err, &stage) && stage.code >= installExitPath && stage.code <= installExitResult {
			return stage.code
		}
	}
	return 1
}

// InstallerResultError keeps output failures distinguishable from native work
// already completed. The public install-plan output keeps its original contract.
func InstallerResultError(err error) error { return installerFailed(installExitResult, err) }
