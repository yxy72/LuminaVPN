//go:build windows

package engine

import (
	"errors"
	"testing"

	"netlaunch/internal/platform"
)

func TestServiceHostDeathReuseAndUnknownTriggerIndependentRecovery(t *testing.T) {
	id := platform.Identity{PID: 71, Birth: "host-creation", OwnerSID: "S-1-5-18", Executable: `C:\Program Files\LuminaVPN\releases\fixture\lumina-service.exe`}
	binding := ServiceRunBinding{ServiceHost: id}
	if err := serviceHostAliveWith(binding, func(int) (platform.Identity, error) { return id, nil }); err != nil {
		t.Fatal("GUI/read disconnect must not alter native host identity", err)
	}
	for _, tc := range []struct {
		name   string
		actual platform.Identity
		err    error
	}{{"host_exited", platform.Identity{}, nil}, {"pid_reused", platform.Identity{PID: id.PID, Birth: "another-creation", OwnerSID: id.OwnerSID, Executable: id.Executable}, nil}, {"unknown", platform.Identity{}, errors.New("access denied")}, {"wrong_image", platform.Identity{PID: id.PID, Birth: id.Birth, OwnerSID: id.OwnerSID, Executable: `C:\user\forged.exe`}, nil}} {
		t.Run(tc.name, func(t *testing.T) {
			if serviceHostAliveWith(binding, func(int) (platform.Identity, error) { return tc.actual, tc.err }) == nil {
				t.Fatal("lost service owner left takeover running")
			}
		})
	}
}
