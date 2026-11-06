package winservice

import (
	"testing"

	p "netlaunch/internal/serviceprotocol"
)

func TestLocalProfileIDUsesTheSameSixteenBytesAsDesktop(t *testing.T) {
	if got := localProfileID(`C:\Users\Example\.netlaunch`); got != "3e2b54e766c0e2f586dda4499696a2c5" {
		t.Fatalf("desktop profile identity drifted: %s", got)
	}
}

func TestOnlyCompleteLocalAbsenceEvidenceAllowsFirstLaunchExit(t *testing.T) {
	good := localAbsenceEvidence{defaultProfile: true, service: presenceAbsent, installation: presenceAbsent, owned: []localPresence{presenceAbsent, presenceAbsent}}
	snapshot, ok := absentSnapshot("profile", good)
	if !ok || snapshot.LocalExitProof == nil || snapshot.LocalExitProof.Source != "LOCALONLY" || !snapshot.LocalExitProof.ServiceAbsent || !snapshot.LocalExitProof.NoOwnedState || !snapshot.Restored || snapshot.RecoveryRequired || snapshot.Desired.Company || snapshot.Desired.Personal || snapshot.ProfileID != "profile" {
		t.Fatalf("complete local evidence not represented safely: %#v", snapshot)
	}
	for _, kind := range []string{"custom", "SCM_denied", "SCM_present", "install_present", "owned_present", "owned_unknown", "empty"} {
		t.Run(kind, func(t *testing.T) {
			bad := good
			bad.owned = append([]localPresence{}, good.owned...)
			switch kind {
			case "custom":
				bad.defaultProfile = false
			case "SCM_denied":
				bad.service = presenceUnknown
			case "SCM_present":
				bad.service = presencePresent
			case "install_present":
				bad.installation = presencePresent
			case "owned_present":
				bad.owned[0] = presencePresent
			case "owned_unknown":
				bad.owned[0] = presenceUnknown
			case "empty":
				bad.owned = nil
			}
			if _, ok := absentSnapshot("profile", bad); ok {
				t.Fatal("incomplete/contradictory evidence produced safe exit")
			}
		})
	}
}

func TestRemoteSnapshotCannotSupplyLocalAbsenceProof(t *testing.T) {
	remote := p.Snapshot{ServiceState: "not_installed", Restored: true, LocalExitProof: &p.LocalExitProof{Source: "LOCALONLY", ServiceAbsent: true, NoOwnedState: true}}
	clean := discardRemoteExitProof(remote)
	if clean.LocalExitProof != nil || clean.ServiceState == "not_installed" || clean.Restored || !clean.RecoveryRequired {
		t.Fatal("RPC claims authorized local-only exit")
	}
}
