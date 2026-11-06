package winservice

import "path/filepath"

// This model has no identity/install/SCM executor dependency. The public plan
// combines native locations with read-only observations only; privileged
// commands use the separate installer-authority constructor.
func installerPlanModel(programFiles, programData string, preflight func(string) string, legacy func(string) error) InstallPlan {
	plan := PreparedInstallPlan()
	plan.TargetRoot = filepath.Join(programFiles, "LuminaVPN")
	plan.DataRoot = filepath.Join(programData, "LuminaVPN", "ServiceState")
	plan.TargetPreflight = preflight(plan.TargetRoot)
	if legacy(plan.TargetRoot) != nil {
		plan.TargetPreflight = "unsafe"
	}
	return plan
}
