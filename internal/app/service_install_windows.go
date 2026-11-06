//go:build windows

package app

import (
	"netlaunch/internal/winservice"
	"time"
)

// Recovery is a distinct SYSTEM SCM role. It never exposes the client pipe,
// starts a channel or loads user credentials; only strict restoration runs.
func NewWindowsRecoveryHost() (*winservice.Host, error) {
	return winservice.NewInstalledRecoveryHost(func(installation winservice.Installation, owners winservice.OwnershipStore, binding winservice.Binding) (winservice.Backend, error) {
		executor, err := winservice.NewFixedExecutor(installation)
		if err != nil {
			return nil, err
		}
		restorations, err := winservice.OpenRecoveryRestorationStore(binding)
		if err != nil {
			return nil, err
		}
		return &fixedLifecycleBackend{owners: owners, deps: serviceBackendDependencies{lifecycle: executor.Lifecycle, pristine: winservice.PristineRecoveryOwnedRuns, restorations: restorations, now: time.Now}}, nil
	})
}
