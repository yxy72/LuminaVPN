package winservice

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestInstallPlanSerializationMatchesFixedInstallerContract(t *testing.T) {
	plan := PreparedInstallPlan()
	// These paths are fixture values, not a native target observation.
	plan.TargetRoot = `C:\Program Files\LuminaVPN`
	plan.DataRoot = `C:\ProgramData\LuminaVPN\ServiceState`
	plan.TargetPreflight = "absent"
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	keys := []string{"version", "schema", "service_name", "image_kind", "image_relative", "account", "auto_connect", "requires_review", "installed", "service_arguments", "supported_entries", "bootstrap_available", "recovery_service_name", "recovery_arguments", "target_preflight", "target_root", "data_root"}
	if len(fields) != len(keys) {
		t.Fatal("installer schema keys changed", len(fields))
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			t.Fatal("installer schema key missing", key)
		}
	}
	if plan.Version != 1 || plan.Schema != "lumina-service-install-v1" || plan.ServiceName != "LuminaVPNService" || plan.RecoveryServiceName != "LuminaVPNRecoveryService" || plan.ImageKind != ServiceImage || plan.AutoConnect || !plan.BootstrapAvailable || !plan.RequiresReview {
		t.Fatal("installer received a broadened or incomplete service contract")
	}
	if !reflect.DeepEqual(plan.ServiceArguments, []string{"--service"}) || !reflect.DeepEqual(plan.RecoveryArguments, []string{"--recover-service"}) {
		t.Fatal("SCM arguments were broadened")
	}
	if len(plan.SupportedEntries) != 7 {
		t.Fatal("fixed installer entries changed")
	}
	seen := map[string]bool{}
	for _, entry := range plan.SupportedEntries {
		if seen[entry] {
			t.Fatal("duplicate fixed installer entry")
		}
		seen[entry] = true
		if _, err := ParseCommand([]string{entry}); err != nil {
			t.Fatal("advertised installer entry is not accepted")
		}
		if _, err := ParseCommand([]string{entry, `C:\untrusted`}); err == nil {
			t.Fatal("fixed installer entry accepted a target path")
		}
	}
	t.Logf("LUMINA_INSTALL_PLAN_FIXTURE_NOT_NATIVE %s", raw)
}
