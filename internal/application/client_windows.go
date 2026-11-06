//go:build windows && windows_client

package application

import (
	"errors"
	"netlaunch/internal/serviceprotocol"
	"netlaunch/internal/winservice"
)

func newDesktopClient() serviceprotocol.Client { return winservice.NewClient() }

func desktopRecoveryEntry() (any, error) {
	installation, err := winservice.LoadInstallation()
	if err != nil {
		return nil, errors.New("reviewed installed recovery entry unavailable")
	}
	image, err := installation.Executable(winservice.ServiceImage)
	if err != nil {
		return nil, errors.New("fixed service recovery image unavailable")
	}
	return map[string]any{"entry_kind": "installed_service_recover", "image": image, "arguments": []string{"--recover"}}, nil
}
