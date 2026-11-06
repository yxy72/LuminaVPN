//go:build windows && windows_client

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"netlaunch/internal/app"
	"netlaunch/internal/winservice"
)

func main() {
	command, err := winservice.ParseCommand(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "This fixed entry accepts only the reviewed SCM service configuration.")
		os.Exit(2)
	}
	switch command {
	case winservice.CommandService:
		err = winservice.RunConfiguredService(app.NewWindowsServiceHost)
	case winservice.CommandRecoverService:
		err = winservice.RunConfiguredRecoveryService(app.NewWindowsRecoveryHost)
	case winservice.CommandPrintPlan:
		var plan winservice.InstallPlan
		plan, err = winservice.InstallerPlan()
		if err == nil {
			err = json.NewEncoder(os.Stdout).Encode(plan)
			if winservice.InstallPlanExitCode(plan, err) != 0 {
				err = fmt.Errorf("unsafe target")
			}
		}
	default:
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		var result winservice.InstallResult
		result, err = winservice.RunInstallerCommand(ctx, command)
		if err == nil {
			err = json.NewEncoder(os.Stdout).Encode(result)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "The protected Windows service is unavailable.")
		os.Exit(1)
	}
}
