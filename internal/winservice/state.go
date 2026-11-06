package winservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"time"

	p "netlaunch/internal/serviceprotocol"
)

type machineControl struct {
	Version            int    `json:"version"`
	AllowedOwnerSID    string `json:"allowed_owner_sid"`
	AllowedLogonSID    string `json:"allowed_logon_sid"`
	AuthenticationID   string `json:"authentication_id"`
	SessionID          uint32 `json:"session_id"`
	ProfileID          string `json:"profile_id"`
	ServiceInstance    string `json:"service_instance"`
	ServiceSID         string `json:"service_sid"`
	ValidationOnly     bool   `json:"validation_only,omitempty"`
	RecoveryServiceSID string `json:"recovery_service_sid"`
	LogonEpoch         string `json:"logon_epoch,omitempty"`
}

func decodeState(data []byte, value any) error {
	if len(data) == 0 || len(data) > p.MaxFrame {
		return errors.New("invalid protected state size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return errors.New("invalid protected state")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("unexpected protected trailing state")
	}
	return nil
}

func (m machineControl) binding() (Binding, error) {
	if m.Version != 1 || !sidText.MatchString(m.AllowedOwnerSID) || m.AllowedOwnerSID == "S-1-5-18" || !sidText.MatchString(m.AllowedLogonSID) || len(m.AuthenticationID) == 0 || len(m.AuthenticationID) > 128 || m.SessionID == 0 || !ValidProfileID(m.ProfileID) || !p.ValidID(m.ServiceInstance) || !sidText.MatchString(m.ServiceSID) {
		return Binding{}, errors.New("invalid enrolled service control")
	}
	return Binding{ProfileID: m.ProfileID, OwnerSID: m.AllowedOwnerSID, LogonSID: m.AllowedLogonSID, AuthenticationID: m.AuthenticationID, SessionID: m.SessionID, ExecutorSID: "S-1-5-18", ServiceInstance: m.ServiceInstance, LogonEpoch: m.LogonEpoch}, nil
}

// protectedStateFiles has only fixed relative state names. Its production
// implementation requires an already-installed protected tree and never
// creates directories, repairs ACLs or reads a path supplied by RPC.
type protectedStateFiles interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
}

type FileOwnershipStore struct {
	mu       sync.Mutex
	files    protectedStateFiles
	expected Binding
}

func newFileOwnershipStore(files protectedStateFiles, expected Binding) (*FileOwnershipStore, error) {
	if files == nil {
		return nil, errors.New("protected ownership files unavailable")
	}
	store := &FileOwnershipStore{files: files, expected: expected}
	if _, err := store.Lookup(expected.ProfileID); err != nil {
		return nil, err
	}
	return store, nil
}
func sameEnrollment(a, b Binding) bool {
	return a.ProfileID == b.ProfileID && a.OwnerSID == b.OwnerSID && a.LogonSID == b.LogonSID && a.AuthenticationID == b.AuthenticationID && a.SessionID == b.SessionID && a.ExecutorSID == b.ExecutorSID && a.ServiceInstance == b.ServiceInstance && a.LogonEpoch == b.LogonEpoch
}
func samePermanentEnrollment(a, b Binding) bool {
	return a.ProfileID == b.ProfileID && a.OwnerSID == b.OwnerSID && a.ExecutorSID == b.ExecutorSID && a.ServiceInstance == b.ServiceInstance
}
func validOwnedBinding(value, expected Binding) bool {
	if !samePermanentEnrollment(value, expected) || !sidText.MatchString(value.LogonSID) || value.AuthenticationID == "" || len(value.AuthenticationID) > 128 || value.SessionID == 0 || value.Revision == 0 || (value.LastRestorationID != "" && !releaseText.MatchString(value.LastRestorationID)) {
		return false
	}
	if value.RunRef == "" {
		return value.Mode == "" && value.Deadline.IsZero() && value.PreparedRunID == "" && value.SpecDigest == ""
	}
	if !p.ValidID(value.RunRef) {
		return false
	}
	if value.Mode == "daily" {
		if !value.Deadline.IsZero() {
			return false
		}
	} else if value.Mode == "validation" {
		if value.Deadline.IsZero() {
			return false
		}
	} else {
		return false
	}
	return (value.PreparedRunID == "" && value.SpecDigest == "") || (engineRunID.MatchString(value.PreparedRunID) && digestText.MatchString(value.SpecDigest))
}
func (s *FileOwnershipStore) read(id string) (Binding, error) {
	if id != s.expected.ProfileID {
		return Binding{}, errors.New("profile is not enrolled")
	}
	data, err := s.files.Read(filepath.Join("bindings", id+".json"))
	if err != nil {
		return Binding{}, err
	}
	var binding Binding
	if decodeState(data, &binding) != nil || !validOwnedBinding(binding, s.expected) {
		return Binding{}, errors.New("protected ownership binding rejected")
	}
	retired, err := retiredEnrollment(s.files, binding)
	if err != nil {
		return Binding{}, err
	}
	if retired {
		if _, err := s.pendingTarget(binding); err != nil {
			return Binding{}, err
		}
		binding.PendingEnrollmentID = enrollmentKey(binding)
	}
	return binding, nil
}
func (s *FileOwnershipStore) Lookup(id string) (Binding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read(id)
}
func (s *FileOwnershipStore) Save(binding Binding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if binding.PendingEnrollmentID != "" || !validOwnedBinding(binding, s.expected) {
		return errors.New("protected ownership update rejected")
	}
	previous, err := s.read(binding.ProfileID)
	if err != nil {
		return err
	}
	if previous.PendingEnrollmentID != "" {
		return errors.New("pending enrollment requires its exact protected publication")
	}
	if !sameEnrollment(binding, previous) {
		return errors.New("ordinary saves cannot rotate enrollment")
	}
	if binding.Revision < previous.Revision {
		return errors.New("ownership revision cannot decrease")
	}
	if previous.RunRef != "" && binding.RunRef == "" {
		receipt, readErr := readRestoration(s.files, binding.LastRestorationID)
		if readErr != nil || !sameEnrollment(receipt.Source, previous) || receipt.Source.RunRef != previous.RunRef || receipt.Source.PreparedRunID != previous.PreparedRunID || receipt.Source.SpecDigest != previous.SpecDigest {
			return errors.New("run clear requires its durable strict restoration receipt")
		}
	}
	if previous.RunRef != "" && binding.RunRef != "" {
		if previous.RunRef != binding.RunRef || previous.Mode != binding.Mode || !previous.Deadline.Equal(binding.Deadline) || previous.ServiceHostPID != binding.ServiceHostPID || previous.ServiceHostBirth != binding.ServiceHostBirth || previous.ServiceHostSHA256 != binding.ServiceHostSHA256 || previous.LifecycleSHA256 != binding.LifecycleSHA256 || (previous.PreparedRunID != "" && (previous.PreparedRunID != binding.PreparedRunID || previous.SpecDigest != binding.SpecDigest)) {
			return errors.New("immutable owned run cannot change")
		}
	}
	data, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	return s.files.Write(filepath.Join("bindings", binding.ProfileID+".json"), data)
}
func (s *FileOwnershipStore) Active() (Binding, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, err := s.read(s.expected.ProfileID)
	return value, value.RunRef != "", err
}
func (s *FileOwnershipStore) Enrolled() (Binding, error) { return s.Lookup(s.expected.ProfileID) }

type FileLedger struct {
	mu    sync.Mutex
	files protectedStateFiles
}
type requestHistory struct {
	ProfileID   string `json:"profile_id"`
	RequestID   string `json:"request_id"`
	OperationID string `json:"operation_id"`
}

func requestHistoryPath(profile, request string) string {
	sum := sha256.Sum256([]byte(profile + "\x00" + request))
	return filepath.Join("operations", "request-"+hex.EncodeToString(sum[:])+".json")
}
func (l *FileLedger) operation(id string) (p.Operation, bool, error) {
	if !p.ValidID(id) {
		return p.Operation{}, false, errors.New("invalid operation history identity")
	}
	data, err := l.files.Read(filepath.Join("operations", id+".json"))
	if errors.Is(err, errProtectedStateMissing) {
		return p.Operation{}, false, nil
	}
	if err != nil {
		return p.Operation{}, false, err
	}
	var operation p.Operation
	if decodeState(data, &operation) != nil || operation.ID != id {
		return operation, false, errors.New("invalid operation history")
	}
	return operation, true, nil
}
func (l *FileLedger) FindOperation(id string) (p.Operation, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.operation(id)
}
func (l *FileLedger) FindRequest(profile, request string) (p.Operation, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	data, err := l.files.Read(requestHistoryPath(profile, request))
	if errors.Is(err, errProtectedStateMissing) {
		return p.Operation{}, false, nil
	}
	if err != nil {
		return p.Operation{}, false, err
	}
	var history requestHistory
	if decodeState(data, &history) != nil || history.ProfileID != profile || history.RequestID != request {
		return p.Operation{}, false, errors.New("invalid request history")
	}
	operation, present, err := l.operation(history.OperationID)
	if err != nil || !present || operation.ProfileID != profile || operation.RequestID != request {
		return p.Operation{}, false, errors.New("request history has no matching operation")
	}
	return operation, true, nil
}

func (l *FileLedger) Save(operation p.Operation) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.files == nil || !p.ValidID(operation.ID) || !p.ValidID(operation.ProfileID) || !p.ValidID(operation.RequestID) || (operation.RunRef != "" && !p.ValidID(operation.RunRef)) || operation.Created.IsZero() || operation.Updated.Before(operation.Created) || operation.Updated.After(time.Now().Add(time.Minute)) {
		return errors.New("invalid bounded operation journal")
	}
	path := filepath.Join("operations", operation.ID+".json")
	data, err := l.files.Read(path)
	if err == nil {
		var previous p.Operation
		if decodeState(data, &previous) != nil || previous.ID != operation.ID || previous.RequestID != operation.RequestID || previous.ProfileID != operation.ProfileID || previous.RunRef != operation.RunRef || previous.Kind != operation.Kind || !previous.Created.Equal(operation.Created) || operation.Updated.Before(previous.Updated) {
			return errors.New("operation identity cannot change")
		}
		if previous.FirstFailure != nil {
			operation.FirstFailure = previous.FirstFailure
			operation.Error = previous.FirstFailure
			operation.Phase = "failed"
		}
	} else if !errors.Is(err, errProtectedStateMissing) {
		return err
	}
	data, err = json.Marshal(operation)
	if err != nil {
		return err
	}
	if err = l.files.Write(path, data); err != nil {
		return err
	}
	index, err := json.Marshal(requestHistory{ProfileID: operation.ProfileID, RequestID: operation.RequestID, OperationID: operation.ID})
	if err != nil {
		return err
	}
	return l.files.Write(requestHistoryPath(operation.ProfileID, operation.RequestID), index)
}

var errProtectedStateMissing = errors.New("protected state file does not exist")
