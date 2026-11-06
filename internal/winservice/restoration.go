package winservice

import (
	"encoding/json"
	"errors"
	"sync"
	"time"
)

type RestorationStore struct {
	mu       sync.Mutex
	files    protectedStateFiles
	enrolled Binding
}
type restorationReceipt struct {
	Version    int             `json:"version"`
	ID         string          `json:"restoration_id"`
	Enrollment Binding         `json:"enrollment"`
	Source     Binding         `json:"source_binding"`
	Scope      string          `json:"scope"`
	Proof      json.RawMessage `json:"proof"`
}
type restorationFlags struct {
	Clean                   bool      `json:"clean"`
	Pristine                bool      `json:"pristine"`
	NeverBound              bool      `json:"never_bound"`
	NeverServed             bool      `json:"never_served"`
	PreparedOnly            bool      `json:"prepared_only"`
	IdentityCensusComplete  bool      `json:"identity_census_complete"`
	IdentityMappingComplete bool      `json:"identity_mapping_complete"`
	AdaptersAbsent          bool      `json:"adapters_absent"`
	ProcessesGone           bool      `json:"processes_gone"`
	NetworkRestored         bool      `json:"network_restored"`
	WFPAbsent               bool      `json:"wfp_absent"`
	IPv6Absent              bool      `json:"ipv6_absent"`
	Errors                  []string  `json:"errors"`
	Started                 time.Time `json:"started_at"`
	Finished                time.Time `json:"finished_at"`
}

func validRestorationProof(scope string, data json.RawMessage) bool {
	var flags restorationFlags
	if len(data) == 0 || len(data) > 1<<20 || json.Unmarshal(data, &flags) != nil || !flags.Clean || len(flags.Errors) > 0 || flags.Started.IsZero() || flags.Finished.Before(flags.Started) {
		return false
	}
	switch scope {
	case "run":
		return flags.IdentityMappingComplete && flags.AdaptersAbsent && flags.ProcessesGone && flags.NetworkRestored && flags.WFPAbsent && flags.IPv6Absent
	case "unprepared":
		return flags.NeverBound && flags.NeverServed && flags.PreparedOnly && flags.IdentityCensusComplete
	case "pristine":
		return flags.Pristine && flags.NeverServed && flags.IdentityCensusComplete
	}
	return false
}
func readRestoration(files protectedStateFiles, id string) (restorationReceipt, error) {
	if !releaseText.MatchString(id) {
		return restorationReceipt{}, errors.New("invalid restoration publication")
	}
	data, err := files.Read("restoration-" + id + ".json")
	if err != nil {
		return restorationReceipt{}, err
	}
	var receipt restorationReceipt
	if decodeState(data, &receipt) != nil || receipt.Version != 1 || receipt.ID != id || !samePermanentEnrollment(receipt.Enrollment, receipt.Source) || !validRestorationScope(receipt.Scope, receipt.Source) || !validRestorationProof(receipt.Scope, receipt.Proof) {
		return receipt, errors.New("strict restoration receipt rejected")
	}
	return receipt, nil
}
func (s *RestorationStore) Save(source Binding, scope string, proof json.RawMessage) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !sameEnrollment(source, s.enrolled) || !validRestorationScope(scope, source) || !validRestorationProof(scope, proof) {
		return "", errors.New("strict restoration evidence required")
	}
	id, err := newID("restore-")
	if err != nil {
		return "", err
	}
	receipt := restorationReceipt{Version: 1, ID: id, Enrollment: s.enrolled, Source: source, Scope: scope, Proof: append(json.RawMessage{}, proof...)}
	data, err := json.Marshal(receipt)
	if err != nil {
		return "", err
	}
	if err = s.files.Write("restoration-"+id+".json", data); err != nil {
		return "", err
	}
	return id, nil
}
func validRestorationScope(scope string, source Binding) bool {
	switch scope {
	case "pristine":
		return source.RunRef == "" && source.PreparedRunID == "" && source.SpecDigest == ""
	case "unprepared":
		return source.RunRef != "" && source.PreparedRunID == "" && source.SpecDigest == ""
	case "run":
		return source.RunRef != "" && engineRunID.MatchString(source.PreparedRunID) && digestText.MatchString(source.SpecDigest)
	}
	return false
}
func (s *RestorationStore) Verify(current Binding) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current.RunRef != "" || current.PreparedRunID != "" || current.SpecDigest != "" || !sameEnrollment(current, s.enrolled) || current.LastRestorationID == "" {
		return false, nil
	}
	receipt, err := readRestoration(s.files, current.LastRestorationID)
	if err != nil {
		return false, err
	}
	if !sameEnrollment(current, receipt.Enrollment) {
		return false, errors.New("restoration belongs to another enrollment")
	}
	return true, nil
}
