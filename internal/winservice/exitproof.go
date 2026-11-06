package winservice

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"

	p "netlaunch/internal/serviceprotocol"
)

func localProfileID(profile string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(profile))))
	return hex.EncodeToString(sum[:16])
}

type localPresence uint8

const (
	presenceUnknown localPresence = iota
	presenceAbsent
	presencePresent
)

// This is a local-only evidence aggregate, never decoded from an RPC frame.
// Any footprint or failed observation prevents the first-launch exit proof.
type localAbsenceEvidence struct {
	defaultProfile bool
	service        localPresence
	installation   localPresence
	owned          []localPresence
}

func absentSnapshot(profile string, evidence localAbsenceEvidence) (p.Snapshot, bool) {
	if !p.ValidID(profile) || !evidence.defaultProfile || evidence.service != presenceAbsent || evidence.installation != presenceAbsent || len(evidence.owned) == 0 {
		return p.Snapshot{}, false
	}
	for _, observed := range evidence.owned {
		if observed != presenceAbsent {
			return p.Snapshot{}, false
		}
	}
	return p.Snapshot{
		ProtocolVersion: p.Version, ProfileID: profile, ServiceState: "not_installed", TakeoverState: "idle",
		Restored: true, Company: p.Channel{State: "off", Route: "none", IPv6: "unknown"}, Personal: p.Channel{State: "off", Route: "direct", IPv6: "unknown"},
		LocalExitProof: &p.LocalExitProof{Source: "LOCALONLY", ServiceAbsent: true, NoOwnedState: true},
	}, true
}

func discardRemoteExitProof(snapshot p.Snapshot) p.Snapshot {
	snapshot.LocalExitProof = nil
	// A reachable RPC server cannot authoritatively claim local absence.
	if snapshot.ServiceState == "not_installed" {
		snapshot.ServiceState = "unknown"
		snapshot.Restored = false
		snapshot.RecoveryRequired = true
	}
	return snapshot
}
