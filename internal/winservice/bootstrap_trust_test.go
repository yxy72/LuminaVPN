package winservice

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBootstrapTrustHasExactFreshInstallerResourceEnvelope(t *testing.T) {
	now := time.Unix(1800000000, 0)
	trust := BootstrapTrust{Version: 1, Product: "LuminaVPN", Purpose: "service-bootstrap", Nonce: strings.Repeat("a", 32), SHA256: strings.Repeat("b", 64), CreatedUnix: now.Unix(), ExpiresUnix: now.Unix() + 1800}
	if trust.Validate(trust.Nonce, now) != nil {
		t.Fatal("fresh trusted envelope rejected")
	}
	for _, alter := range []func(*BootstrapTrust){func(v *BootstrapTrust) { v.Nonce = strings.Repeat("c", 32) }, func(v *BootstrapTrust) { v.ExpiresUnix++ }, func(v *BootstrapTrust) { v.CreatedUnix++; v.ExpiresUnix++ }, func(v *BootstrapTrust) { v.Purpose = "arbitrary" }, func(v *BootstrapTrust) { v.SHA256 = "missing" }} {
		bad := trust
		alter(&bad)
		if bad.Validate(trust.Nonce, now) == nil {
			t.Fatal("stale/mismatched bootstrap authority accepted")
		}
	}
	if trust.Validate(trust.Nonce, time.Unix(trust.ExpiresUnix, 0)) == nil {
		t.Fatal("expired bootstrap accepted")
	}
	raw, _ := json.Marshal(trust)
	var fields map[string]any
	json.Unmarshal(raw, &fields)
	if len(fields) != 7 {
		t.Fatal("bootstrap trust schema drift")
	}
}
func TestInstallerPlanLiteralSchemaAndExitMapping(t *testing.T) {
	plan := PreparedInstallPlan()
	plan.TargetRoot = `C:\Program Files\LuminaVPN`
	plan.DataRoot = `C:\ProgramData\LuminaVPN\ServiceState`
	plan.TargetPreflight = "absent"
	raw, _ := json.Marshal(plan)
	var fields map[string]any
	json.Unmarshal(raw, &fields)
	if len(fields) != 17 || plan.Version != 1 || plan.Schema != "lumina-service-install-v1" || plan.ServiceName != ServiceName || plan.RecoveryServiceName != RecoveryServiceName || !plan.BootstrapAvailable || !plan.RequiresReview || plan.Installed || plan.AutoConnect || strings.Contains(plan.Account, "minimum") {
		t.Fatalf("installer plan contract drifted: %s", raw)
	}
	expected := []string{"--service", "--bootstrap", "--recover-service", "--recover", "--uninstall", "--print-install-plan", "--resume-install-preflight"}
	if !reflect.DeepEqual(plan.SupportedEntries, expected) || !reflect.DeepEqual(plan.ServiceArguments, []string{"--service"}) || !reflect.DeepEqual(plan.RecoveryArguments, []string{"--recover-service"}) {
		t.Fatal("fixed installer entries drifted")
	}
	for _, state := range []string{"absent", "protected", "unsafe", "unknown"} {
		plan.TargetPreflight = state
		expected := 1
		if state == "absent" || state == "protected" {
			expected = 0
		}
		if InstallPlanExitCode(plan, nil) != expected {
			t.Fatal("unsafe/unknown preflight was not a nonzero exit")
		}
	}
}
func TestLegacyUninstallRegistryValueHasNoAlternatePathOrArguments(t *testing.T) {
	root := `C:\Program Files\LuminaVPN`
	good := `"C:\Program Files\LuminaVPN\Uninstall LuminaVPN.exe" /allusers`
	if !fixedUninstallString(root, root, good) {
		t.Fatal("fixed protected target literal rejected")
	}
	for _, command := range []string{good + " /S", good + " & calc", good + " /allusers", strings.TrimSuffix(good, " /allusers"), `"C:\Users\Example\Uninstall LuminaVPN.exe" /allusers`, `cmd /c uninstall`, strings.Trim(good, `"`)} {
		if fixedUninstallString(root, root, command) {
			t.Fatal("unsafe registry uninstall command accepted")
		}
	}
	if fixedUninstallString(root, `C:\Users\Example`, good) {
		t.Fatal("user install location silently adopted")
	}
	if len(luminaUninstallID()) != 36 {
		t.Fatal("NSIS product UUID malformed")
	}
}
func TestPublicReadOnlyPlanNeedsNoBootstrapOrCallerAuthority(t *testing.T) {
	var observations []string
	plan := installerPlanModel("native-programfiles", "native-programdata", func(target string) string {
		observations = append(observations, "read-target:"+target)
		return "absent"
	}, func(target string) error { observations = append(observations, "read-registry:"+target); return nil })
	target := filepath.Join("native-programfiles", "LuminaVPN")
	if !reflect.DeepEqual(observations, []string{"read-target:" + target, "read-registry:" + target}) || plan.TargetRoot != target || InstallPlanExitCode(plan, nil) != 0 {
		t.Fatal("read-only build-stage plan acquired privileged prerequisites")
	}
	plan = installerPlanModel("native-programfiles", "native-programdata", func(string) string { return "protected" }, func(string) error { return errors.New("unknown uninstall string") })
	if InstallPlanExitCode(plan, nil) != 1 {
		t.Fatal("public plan ignored unsafe legacy entry")
	}
}
