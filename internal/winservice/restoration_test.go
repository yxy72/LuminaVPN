package winservice

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fixtureRunRestoration(t *testing.T, files *memoryStateFiles, source Binding) string {
	t.Helper()
	now := time.Now()
	proof, _ := json.Marshal(map[string]any{"clean": true, "identity_mapping_complete": true, "adapters_absent": true, "processes_gone": true, "network_restored": true, "wfp_absent": true, "ipv6_absent": true, "errors": []string{}, "started_at": now, "finished_at": now})
	store := &RestorationStore{files: files, enrolled: source}
	id, err := store.Save(source, "run", proof)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func TestRestorationPublicationSurvivesRestartAndConfigurationRevision(t *testing.T) {
	files, source := fixtureStateFiles(t)
	source.RunRef = "run-A"
	source.Mode = "daily"
	source.PreparedRunID = "netlaunch-" + strings.Repeat("a", 32)
	source.SpecDigest = strings.Repeat("b", 64)
	id := fixtureRunRestoration(t, files, source)
	current := source
	clearRunBinding(&current)
	current.LastRestorationID = id
	current.Revision += 5
	restarted := &RestorationStore{files: files, enrolled: source}
	if clean, err := restarted.Verify(current); err != nil || !clean {
		t.Fatal("published strict proof was lost after service restart/config save")
	}
	current.RunRef = "new-run"
	current.Mode = "daily"
	current.LastRestorationID = ""
	if clean, _ := restarted.Verify(current); clean {
		t.Fatal("new run reused an old restoration receipt")
	}
}
func TestUnknownReceiptAndBlindRunClearFailClosed(t *testing.T) {
	files, expected := fixtureStateFiles(t)
	source := expected
	source.RunRef = "run-A"
	source.Mode = "daily"
	source.PreparedRunID = "netlaunch-" + strings.Repeat("a", 32)
	source.SpecDigest = strings.Repeat("b", 64)
	owned, _ := newFileOwnershipStore(files, expected)
	if err := owned.Save(source); err != nil {
		t.Fatal(err)
	}
	cleared := source
	clearRunBinding(&cleared)
	if owned.Save(cleared) == nil {
		t.Fatal("active run cleared without durable strict proof")
	}
	cleared.LastRestorationID = "restore-missing"
	if owned.Save(cleared) == nil {
		t.Fatal("missing receipt accepted")
	}
	id := fixtureRunRestoration(t, files, source)
	cleared.LastRestorationID = id
	if err := owned.Save(cleared); err != nil {
		t.Fatal("strict proof did not permit exact publication", err)
	}
	store := &RestorationStore{files: files, enrolled: source}
	files.files["restoration-"+id+".json"] = []byte(`{"version":1}`)
	if clean, err := store.Verify(cleared); err == nil || clean {
		t.Fatal("corrupted protected history became clean")
	}
}
