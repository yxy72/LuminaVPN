//go:build windows

package winservice

import (
	"reflect"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestVerifyPipeServiceRequiresExactSCMIdentity(t *testing.T) {
	const image = `C:\Program Files\LuminaVPN\releases\reviewed\lumina-service.exe`
	const pipePID = 42
	for _, test := range []struct {
		name   string
		change func(*svc.Status, *mgr.Config)
		want   []string
	}{
		{"ordinary SCM reads", func(*svc.Status, *mgr.Config) {}, []string{"status", "config", "status"}},
		{"other pipe owner", func(s *svc.Status, _ *mgr.Config) { s.ProcessId++ }, []string{"status"}},
		{"zero SCM PID", func(s *svc.Status, _ *mgr.Config) { s.ProcessId = 0 }, []string{"status"}},
		{"start pending", func(s *svc.Status, _ *mgr.Config) { s.State = svc.StartPending }, []string{"status"}},
		{"stop pending", func(s *svc.Status, _ *mgr.Config) { s.State = svc.StopPending }, []string{"status"}},
		{"other image", func(_ *svc.Status, c *mgr.Config) {
			c.BinaryPathName = windows.EscapeArg(`C:\Temp\lumina-service.exe`) + " --service"
		}, []string{"status", "config"}},
		{"extra arguments", func(_ *svc.Status, c *mgr.Config) { c.BinaryPathName += " --uninstall" }, []string{"status", "config"}},
		{"different entry", func(_ *svc.Status, c *mgr.Config) {
			c.BinaryPathName = windows.EscapeArg(image) + " --recover-service"
		}, []string{"status", "config"}},
		{"other account", func(_ *svc.Status, c *mgr.Config) { c.ServiceStartName = "LocalService" }, []string{"status", "config"}},
		{"shared process", func(_ *svc.Status, c *mgr.Config) { c.ServiceType = windows.SERVICE_WIN32_SHARE_PROCESS }, []string{"status", "config"}},
		{"missing service SID", func(_ *svc.Status, c *mgr.Config) { c.SidType = windows.SERVICE_SID_TYPE_NONE }, []string{"status", "config"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			status := svc.Status{State: svc.Running, ProcessId: pipePID}
			config := mgr.Config{
				BinaryPathName: windows.EscapeArg(image) + " --service", ServiceStartName: "LocalSystem",
				ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED,
			}
			test.change(&status, &config)
			var calls []string
			err := verifyPipeService(pipePID, image, func() (svc.Status, error) {
				calls = append(calls, "status")
				return status, nil
			}, func() (mgr.Config, error) {
				calls = append(calls, "config")
				return config, nil
			})
			if (err == nil) != (len(test.want) == 3) || !reflect.DeepEqual(calls, test.want) {
				t.Fatalf("unexpected verification: %v, calls %v", err, calls)
			}
		})
	}
}

func TestVerifyPipeServiceRejectsChangedSCMReadback(t *testing.T) {
	const image = `C:\Program Files\LuminaVPN\releases\reviewed\lumina-service.exe`
	const pipePID = 42
	config := mgr.Config{
		BinaryPathName: windows.EscapeArg(image) + " --service", ServiceStartName: "LocalSystem",
		ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
	for _, test := range []struct {
		name   string
		status svc.Status
		err    error
	}{
		{"restarted process", svc.Status{State: svc.Running, ProcessId: pipePID + 1}, nil},
		{"service stopping", svc.Status{State: svc.StopPending, ProcessId: pipePID}, nil},
		{"unknown service", svc.Status{}, windows.ERROR_ACCESS_DENIED},
	} {
		t.Run(test.name, func(t *testing.T) {
			observations := 0
			err := verifyPipeService(pipePID, image, func() (svc.Status, error) {
				observations++
				if observations == 1 {
					return svc.Status{State: svc.Running, ProcessId: pipePID}, nil
				}
				return test.status, test.err
			}, func() (mgr.Config, error) {
				return config, nil
			})
			if err == nil || observations != 2 {
				t.Fatal("pipe identity was accepted without a second matching running service observation")
			}
		})
	}
}
