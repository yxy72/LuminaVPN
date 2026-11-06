package winservice

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	p "netlaunch/internal/serviceprotocol"
)

type memoryStateFiles struct {
	files     map[string][]byte
	failWrite bool
}

func (f *memoryStateFiles) Read(path string) ([]byte, error) {
	data, ok := f.files[path]
	if !ok {
		return nil, errProtectedStateMissing
	}
	return append([]byte{}, data...), nil
}
func (f *memoryStateFiles) Write(path string, data []byte) error {
	if f.failWrite {
		return errors.New("simulated durable write failure")
	}
	f.files[path] = append([]byte{}, data...)
	return nil
}
func fixtureStateFiles(t *testing.T) (*memoryStateFiles, Binding) {
	t.Helper()
	binding := testBinding("profile")
	data, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	return &memoryStateFiles{files: map[string][]byte{filepath.Join("bindings", "profile.json"): data}}, binding
}

func TestProtectedOwnershipStoreRejectsForeignEnrollmentAndRunMutation(t *testing.T) {
	files, expected := fixtureStateFiles(t)
	store, err := newFileOwnershipStore(files, expected)
	if err != nil {
		t.Fatal(err)
	}
	binding := expected
	binding.RunRef = "run-A"
	binding.Mode = "validation"
	binding.Deadline = time.Now().Add(time.Minute)
	binding.PreparedRunID = "netlaunch-" + strings.Repeat("a", 32)
	binding.SpecDigest = strings.Repeat("b", 64)
	if err = store.Save(binding); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Binding){func(b *Binding) { b.OwnerSID = "S-1-5-21-2" }, func(b *Binding) { b.SessionID++ }, func(b *Binding) { b.ExecutorSID = "S-1-5-19" }, func(b *Binding) { b.RunRef = "run-B" }, func(b *Binding) { b.Deadline = b.Deadline.Add(time.Second) }, func(b *Binding) { b.Mode = "daily"; b.Deadline = time.Time{} }, func(b *Binding) { b.PreparedRunID = "netlaunch-" + strings.Repeat("c", 32) }, func(b *Binding) { b.SpecDigest = strings.Repeat("d", 64) }} {
		altered := binding
		change(&altered)
		if store.Save(altered) == nil {
			t.Fatalf("foreign or mutable run accepted: %#v", altered)
		}
	}
	if _, err = store.Lookup("other"); err == nil {
		t.Fatal("unenrolled profile accepted")
	}
	if active, ok, err := store.Active(); err != nil || !ok || active.PreparedRunID != binding.PreparedRunID {
		t.Fatal("durable active identity missing")
	}
	clearRunBinding(&binding)
	source, _ := store.Lookup("profile")
	proof, _ := json.Marshal(map[string]any{"clean": true, "identity_mapping_complete": true, "adapters_absent": true, "processes_gone": true, "network_restored": true, "wfp_absent": true, "ipv6_absent": true, "started_at": time.Now(), "finished_at": time.Now()})
	restorations := &RestorationStore{files: files, enrolled: expected}
	binding.LastRestorationID, err = restorations.Save(source, "run", proof)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Save(binding); err != nil {
		t.Fatal(err)
	}
	if _, active, err := store.Active(); err != nil || active {
		t.Fatal("cleared run stayed active")
	}
}

func TestMissingOrMalformedOwnershipNeverCreatesAProfile(t *testing.T) {
	files, expected := fixtureStateFiles(t)
	delete(files.files, filepath.Join("bindings", "profile.json"))
	if _, err := newFileOwnershipStore(files, expected); err == nil {
		t.Fatal("missing installer binding became ready")
	}
	files.files[filepath.Join("bindings", "profile.json")] = []byte(`{"profile_id":"profile","command":"powershell"}`)
	if _, err := newFileOwnershipStore(files, expected); err == nil {
		t.Fatal("malformed binding became ready")
	}
	if len(files.files) != 1 {
		t.Fatal("store provisioned files")
	}
}

func TestFileLedgerPreservesFirstFailureAndImmutableIdentity(t *testing.T) {
	files, _ := fixtureStateFiles(t)
	ledger := &FileLedger{files: files}
	now := time.Now()
	op := p.Operation{ID: "op-one", ProfileID: "profile", RequestID: "request", Kind: p.ExitRestore, Created: now, Updated: now, Phase: "failed", Error: safeError("FIRST"), FirstFailure: safeError("FIRST")}
	if err := ledger.Save(op); err != nil {
		t.Fatal(err)
	}
	op.Updated = now.Add(time.Millisecond)
	op.Error = nil
	op.FirstFailure = nil
	op.Phase = "completed"
	op.Completed = true
	op.Restored = true
	if err := ledger.Save(op); err != nil {
		t.Fatal(err)
	}
	data, _ := files.Read(filepath.Join("operations", "op-one.json"))
	var saved p.Operation
	if decodeState(data, &saved) != nil || saved.FirstFailure == nil || saved.FirstFailure.Code != "FIRST" || saved.Error == nil || saved.Phase != "failed" {
		t.Fatal("later success erased first failure")
	}
	op.ProfileID = "foreign"
	if ledger.Save(op) == nil {
		t.Fatal("operation enrollment changed")
	}
	op.ProfileID = "profile"
	files.failWrite = true
	if ledger.Save(op) == nil {
		t.Fatal("write failure ignored")
	}
}

func TestMachineControlIsTypedAndCannotEnrollSystemOrSessionZero(t *testing.T) {
	valid := machineControl{Version: 1, AllowedOwnerSID: "S-1-5-21-1", AllowedLogonSID: "S-1-5-5-1-1", AuthenticationID: "auth-1", SessionID: 1, ProfileID: "profile", ServiceInstance: "instance", ServiceSID: "S-1-5-80-1"}
	if _, err := valid.binding(); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*machineControl){func(c *machineControl) { c.AllowedOwnerSID = "S-1-5-18" }, func(c *machineControl) { c.SessionID = 0 }, func(c *machineControl) { c.ProfileID = "../path" }, func(c *machineControl) { c.ServiceSID = "S-1-5-80;GA" }} {
		bad := valid
		alter(&bad)
		if _, err := bad.binding(); err == nil {
			t.Fatal("invalid machine control accepted")
		}
	}
	var control machineControl
	if decodeState([]byte(`{"version":1,"exe":"C:\\user.exe"}`), &control) == nil {
		t.Fatal("unknown machine execution field accepted")
	}
}
