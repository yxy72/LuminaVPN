package app

import (
	"netlaunch/internal/buildinfo"
	"testing"
)

func TestExplicitClientBuildIdentityDoesNotChangeDefaultOrMac(t *testing.T) {
	info := buildinfo.Current()
	client := describeClientBuild(info, "windows", false, false, true)
	if client.Mode != "windows_client" || !client.Capabilities.NativeLifecycle || !client.Capabilities.DailyWithoutFixedTTL || !client.Capabilities.RequiresInstalledService || client.Capabilities.ValidationMaximumSeconds != 2700 || client.Capabilities.SessionCacheMaximumSeconds != 7200 {
		t.Fatal("client identity differs from its explicit compiled capabilities")
	}
	if client.Capabilities.DefaultSessionSeconds != 0 || client.Capabilities.MaximumSessionSeconds != 0 {
		t.Fatal("daily client accidentally inherited legacy TTL")
	}
	if b := describeBuild(info, "windows", false, false); b.Mode != "windows_offline" || b.Capabilities.NativeLifecycle || b.Capabilities.WindowsClient {
		t.Fatal("default Windows gate changed")
	}
	if b := describeClientBuild(info, "windows", true, false, true); b.Mode != "invalid_windows_tags" || b.Capabilities.NativeLifecycle {
		t.Fatal("mixed client and legacy gates accepted")
	}
	if b := describeClientBuild(info, "darwin", false, false, true); b.Mode != "macos_experimental" || b.Capabilities.WindowsClient || b.Capabilities.DailyWithoutFixedTTL {
		t.Fatal("Windows client altered Mac capabilities")
	}
}
