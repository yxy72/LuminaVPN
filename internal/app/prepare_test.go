package app

import (
	"bytes"
	"encoding/json"
	"netlaunch/internal/testutil"
	"os"
	"path/filepath"
	"testing"
)

func TestPreparedRunDoesNotClaimReadyOrInvokeAuthorization(t *testing.T) {
	var out bytes.Buffer
	run := filepath.Join(testutil.PrivateTempDir(t), "netlaunch-prepared")
	if e := (CLI{Out: &out}).prepared(run); e != nil {
		t.Fatal(e)
	}
	var result struct {
		Phase          string `json:"phase"`
		NetworkChanges bool   `json:"network_changes"`
		Authorization  bool   `json:"administrator_authorization_requested"`
	}
	if e := json.Unmarshal(out.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	if result.Phase != "prepared" || result.NetworkChanges || result.Authorization {
		t.Fatal(result)
	}
	status, e := statusFor(run)
	if e != nil || status.Phase != "prepared" || status.Company != "unavailable" || status.Personal != "REJECT" {
		t.Fatal(status, e)
	}
	files, e := os.ReadDir(run)
	if e != nil || len(files) != 1 || files[0].Name() != "status.json" {
		t.Fatal(files, e)
	}
}

func TestPreparationFlagCannotBeSilentlyIgnored(t *testing.T) {
	if e := (CLI{}).Run([]string{"auth", "--prepare-only"}); e == nil {
		t.Fatal("flag silently ignored on authentication")
	}
}
