package winservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
)

type enrollmentRotator interface {
	Retired(Binding) (bool, error)
	Rotate(Binding, Binding) (Binding, error)
}
type enrollmentRepairer interface {
	PendingTarget(Binding) (Binding, error)
}
type retiredEnrollmentRecord struct {
	Version int      `json:"version"`
	Binding Binding  `json:"binding"`
	Target  *Binding `json:"target,omitempty"`
}

// pendingTarget accepts only the intent published after the old resources were
// strictly restored. Both protected receipts must retain the exact same source
// and proof; the target identity is never reconstructed from a later caller.
func (s *FileOwnershipStore) pendingTarget(previous Binding) (Binding, error) {
	key := enrollmentKey(previous)
	if previous.PendingEnrollmentID != "" && previous.PendingEnrollmentID != key {
		return Binding{}, errors.New("invalid pending enrollment identity")
	}
	previous.PendingEnrollmentID = ""
	data, err := s.files.Read("retired-login-" + key + ".json")
	if err != nil {
		return Binding{}, err
	}
	var intent retiredEnrollmentRecord
	if decodeState(data, &intent) != nil || intent.Version != 1 || intent.Binding != previous || intent.Target == nil {
		return Binding{}, errors.New("retired enrollment has no complete publication intent")
	}
	target := *intent.Target
	if target.PendingEnrollmentID != "" || !validOwnedBinding(target, s.expected) || !samePermanentEnrollment(previous, target) || sameEnrollment(previous, target) || target.Revision != previous.Revision+1 || previous.RunRef != "" || target.RunRef != "" || target.LogonEpoch == "" || target.LastRestorationID == "" || target.LastRestorationID == previous.LastRestorationID {
		return Binding{}, errors.New("invalid enrollment publication target")
	}
	retired, err := retiredEnrollment(s.files, target)
	if err != nil || retired {
		return Binding{}, errors.New("publication target is retired or unknown")
	}
	prior, err := readRestoration(s.files, previous.LastRestorationID)
	if err != nil || !sameEnrollment(prior.Enrollment, previous) {
		return Binding{}, errors.New("original strict restoration publication unavailable")
	}
	next, err := readRestoration(s.files, target.LastRestorationID)
	if err != nil || next.Enrollment != target || next.Source != prior.Source || next.Scope != prior.Scope || !bytes.Equal(next.Proof, prior.Proof) {
		return Binding{}, errors.New("target strict restoration publication conflicts")
	}
	return target, nil
}
func (s *FileOwnershipStore) PendingTarget(previous Binding) (Binding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.read(previous.ProfileID)
	if err != nil || current != previous || current.PendingEnrollmentID == "" {
		return Binding{}, errors.New("no exact pending enrollment")
	}
	return s.pendingTarget(current)
}

func enrollmentKey(binding Binding) string {
	data, _ := json.Marshal([]any{binding.ProfileID, binding.OwnerSID, binding.LogonSID, binding.AuthenticationID, binding.SessionID, binding.LogonEpoch})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func retiredEnrollment(files protectedStateFiles, binding Binding) (bool, error) {
	data, err := files.Read("retired-login-" + enrollmentKey(binding) + ".json")
	if errors.Is(err, errProtectedStateMissing) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var retired retiredEnrollmentRecord
	if decodeState(data, &retired) != nil || retired.Version != 1 || !sameEnrollment(retired.Binding, binding) {
		return false, errors.New("invalid retired login record")
	}
	return true, nil
}
func (s *FileOwnershipStore) Retired(binding Binding) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !samePermanentEnrollment(binding, s.expected) {
		return false, errors.New("foreign enrollment")
	}
	return retiredEnrollment(s.files, binding)
}
func (s *FileOwnershipStore) Rotate(previous, target Binding) (Binding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.read(previous.ProfileID)
	if err == nil && current == previous && current.PendingEnrollmentID != "" {
		planned, planErr := s.pendingTarget(current)
		if planErr != nil || target != planned {
			return Binding{}, errors.New("only the exact protected enrollment target may resume")
		}
		data, marshalErr := json.Marshal(planned)
		if marshalErr != nil {
			return Binding{}, marshalErr
		}
		if err = s.files.Write(filepath.Join("bindings", planned.ProfileID+".json"), data); err != nil {
			return Binding{}, err
		}
		return planned, nil
	}
	if err != nil || current != previous || current.RunRef != "" || current.LastRestorationID == "" || target.PendingEnrollmentID != "" || target.RunRef != "" || target.PreparedRunID != "" || target.SpecDigest != "" || !samePermanentEnrollment(current, target) || sameEnrollment(current, target) || target.Revision != current.Revision+1 || target.LogonEpoch == "" || !validOwnedBinding(target, s.expected) {
		return Binding{}, errors.New("strict restored enrollment rotation required")
	}
	retired, err := retiredEnrollment(s.files, target)
	if err != nil || retired {
		return Binding{}, errors.New("login session is retired")
	}
	receipt, err := readRestoration(s.files, current.LastRestorationID)
	if err != nil || !sameEnrollment(receipt.Enrollment, current) {
		return Binding{}, errors.New("rotation has no exact prior restoration publication")
	}
	id, err := newID("restore-")
	if err != nil {
		return Binding{}, err
	}
	receipt.ID = id
	target.LastRestorationID = id
	receipt.Enrollment = target
	data, err := json.Marshal(receipt)
	if err != nil {
		return Binding{}, err
	}
	if err = s.files.Write("restoration-"+id+".json", data); err != nil {
		return Binding{}, err
	}
	data, _ = json.Marshal(retiredEnrollmentRecord{Version: 1, Binding: current, Target: &target})
	if err = s.files.Write("retired-login-"+enrollmentKey(current)+".json", data); err != nil {
		return Binding{}, err
	}
	target.LastRestorationID = id
	data, _ = json.Marshal(target)
	if err = s.files.Write(filepath.Join("bindings", target.ProfileID+".json"), data); err != nil {
		return Binding{}, err
	}
	return target, nil
}
func (m *MemoryStore) Retired(binding Binding) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.RetiredLogins[enrollmentKey(binding)], nil
}
func (m *MemoryStore) Rotate(previous, target Binding) (Binding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.Bindings[previous.ProfileID]
	if !ok || current != previous || current.RunRef != "" || !samePermanentEnrollment(current, target) || m.RetiredLogins[enrollmentKey(target)] {
		return Binding{}, errors.New("unsafe mock enrollment rotation")
	}
	if m.RetiredLogins == nil {
		m.RetiredLogins = map[string]bool{}
	}
	m.RetiredLogins[enrollmentKey(current)] = true
	m.Bindings[target.ProfileID] = target
	return target, nil
}
