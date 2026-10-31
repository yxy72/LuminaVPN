package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/testutil"
)

func versionFixture(t *testing.T) (string, policy.Config, policy.Config) {
	t.Helper()
	profile := testutil.PrivateTempDir(t)
	base, err := policy.Decode([]byte(Example))
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.Write(filepath.Join(profile, "policy.json"), base); err != nil {
		t.Fatal(err)
	}
	nodes := []policy.Node{{"type": "vless", "server": "203.0.113.7", "port": 443, "uuid": "fixture-only-secret", "tls": true}}
	if err := securefile.Write(filepath.Join(profile, "nodes.json"), nodes); err != nil {
		t.Fatal(err)
	}
	candidate := base
	candidate.PersonalRules = []policy.Rule{{Type: "DOMAIN", Value: "changed.example.org", Target: "reject"}}
	return profile, base, candidate
}

func TestConfigurationDiffApplyHistoryAndRollbackOffline(t *testing.T) {
	profile, base, candidate := versionFixture(t)
	path := filepath.Join(profile, "candidate.json")
	if err := securefile.Write(path, candidate); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cli := CLI{Out: &out, Err: &out}
	if err := cli.Run([]string{"config", "diff", "--file", path, "--profile", profile}); err != nil {
		t.Fatal(err)
	}
	var diff struct {
		Changed []configFieldChange `json:"changed_fields"`
		Rules   bool                `json:"rule_plan_changed"`
	}
	if err := json.Unmarshal(out.Bytes(), &diff); err != nil || !diff.Rules || len(diff.Changed) != 1 || diff.Changed[0].Field != "personal_rules" {
		t.Fatal(diff, err)
	}
	if got, _ := readPolicy(profile); policyRevision(got) != policyRevision(base) {
		t.Fatal("diff wrote policy")
	}
	out.Reset()
	if err := cli.Run([]string{"config", "apply", "--file", path, "--profile", profile}); err != nil {
		t.Fatal(err)
	}
	var applied configChangeResult
	if err := json.Unmarshal(out.Bytes(), &applied); err != nil || applied.Revision != policyRevision(candidate) || applied.Previous != policyRevision(base) || applied.AppliesTo != "next_start" {
		t.Fatal(applied, err)
	}
	if err := requireCompleteConfigTransaction(profile); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := cli.Run([]string{"config", "history", "--profile", profile}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), policyRevision(base)) || !strings.Contains(out.String(), policyRevision(candidate)) || strings.Contains(out.String(), "fixture-only-secret") {
		t.Fatal(out.String())
	}
	if err := cli.Run([]string{"config", "rollback", "--profile", profile}); err != nil {
		t.Fatal(err)
	}
	if got, _ := readPolicy(profile); policyRevision(got) != policyRevision(base) {
		t.Fatal("rollback did not restore policy")
	}
	if err := cli.Run([]string{"config", "rollback", "--revision", policyRevision(candidate), "--profile", profile}); err != nil {
		t.Fatal(err)
	}
	if got, _ := readPolicy(profile); policyRevision(got) != policyRevision(candidate) {
		t.Fatal("explicit revision ignored")
	}
	for _, entry := range []string{"../policy", strings.Repeat("A", 64), strings.Repeat("0", 64)} {
		if err := cli.Run([]string{"config", "rollback", "--revision", entry, "--profile", profile}); err == nil {
			t.Fatal("invalid/missing revision accepted")
		}
	}
	files, err := os.ReadDir(filepath.Join(profile, "config-revisions"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range files {
		raw, err := securefile.Read(filepath.Join(profile, "config-revisions", entry.Name()), 1<<20, true)
		if err != nil || bytes.Contains(raw, []byte("fixture-only-secret")) || bytes.Contains(raw, []byte("cookie")) {
			t.Fatal("revision contains secrets or is not private", err)
		}
	}
}

func TestConfigRestartFailureRestoresOnlyAfterRecovery(t *testing.T) {
	for _, failAt := range []string{"stop", "start", "cleanup", "none", "external_edit"} {
		t.Run(failAt, func(t *testing.T) {
			profile, base, candidate := versionFixture(t)
			events := []string{}
			stops := 0
			life := configLifecycle{
				running: func() (bool, error) { return true, nil },
				stop: func() error {
					events = append(events, "stop")
					stops++
					if failAt == "stop" || (failAt == "cleanup" && stops == 2) {
						return errors.New("fixture recovery failed")
					}
					return nil
				},
				start: func(cfg policy.Config, nodes []policy.Node) error {
					events = append(events, "start")
					if got, _ := readPolicy(profile); policyRevision(got) != policyRevision(candidate) || len(nodes) != 1 || policyRevision(cfg) != policyRevision(candidate) {
						t.Fatal("candidate not installed/validated before restart")
					}
					if failAt == "external_edit" {
						edited := base
						edited.DirectDNS = []string{"192.0.2.54"}
						if err := securefile.Write(filepath.Join(profile, "policy.json"), edited); err != nil {
							t.Fatal(err)
						}
					}
					if failAt != "none" {
						return errors.New("fixture startup failed")
					}
					return nil
				},
			}
			result, err := changeConfig(profile, candidate, true, false, life)
			if (err == nil) != (failAt == "none") {
				t.Fatal(result, err)
			}
			got, readErr := readPolicy(profile)
			if readErr != nil {
				t.Fatal(readErr)
			}
			tx, readErr := readConfigTransaction(profile)
			if readErr != nil {
				t.Fatal(readErr)
			}
			switch failAt {
			case "stop":
				if !reflect.DeepEqual(events, []string{"stop"}) || policyRevision(got) != policyRevision(base) || tx.Phase != "aborted" {
					t.Fatal(events, tx)
				}
			case "start":
				if !reflect.DeepEqual(events, []string{"stop", "start", "stop"}) || policyRevision(got) != policyRevision(base) || tx.Phase != "rolled_back" {
					t.Fatal(events, tx)
				}
			case "cleanup":
				if policyRevision(got) != policyRevision(candidate) || !tx.pending() || requireCompleteConfigTransaction(profile) == nil {
					t.Fatal("incomplete recovery silently committed")
				}
			case "external_edit":
				if policyRevision(got) == policyRevision(base) || policyRevision(got) == policyRevision(candidate) || !tx.pending() {
					t.Fatal("external edit overwritten")
				}
			case "none":
				if !reflect.DeepEqual(events, []string{"stop", "start"}) || result.AppliesTo != "running" || result.RestartRequired || tx.Phase != "committed" {
					t.Fatal(events, tx)
				}
			}
		})
	}
}

func TestInterruptedConfigChangeRepairsOriginalRevision(t *testing.T) {
	for _, phase := range []string{"prepared", "installed", "recovery_required"} {
		t.Run(phase, func(t *testing.T) {
			profile, base, candidate := versionFixture(t)
			from, err := saveRevision(profile, base)
			if err != nil {
				t.Fatal(err)
			}
			to, err := saveRevision(profile, candidate)
			if err != nil {
				t.Fatal(err)
			}
			head := configHead{Version: 1, Current: from}
			tx := configTransaction{Version: 1, Phase: phase, From: from, To: to, Before: head, Created: time.Now(), Restart: true}
			if err := securefile.Write(filepath.Join(profile, "config-head.json"), head); err != nil {
				t.Fatal(err)
			}
			if err := securefile.Write(filepath.Join(profile, "config-transaction.json"), tx); err != nil {
				t.Fatal(err)
			}
			if phase != "prepared" {
				if err := securefile.Write(filepath.Join(profile, "policy.json"), candidate); err != nil {
					t.Fatal(err)
				}
			}
			if requireCompleteConfigTransaction(profile) == nil {
				t.Fatal("unfinished transaction accepted")
			}
			if err := (CLI{}).Run([]string{"config", "rollback", "--profile", profile}); err != nil {
				t.Fatal(err)
			}
			got, err := readPolicy(profile)
			if err != nil || policyRevision(got) != from {
				t.Fatal("original revision not restored", err)
			}
			if err := requireCompleteConfigTransaction(profile); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInvalidCandidateAndConcurrentApplyCannotChangeConfiguration(t *testing.T) {
	profile, base, candidate := versionFixture(t)
	candidate.Company.CIDRs = []string{"203.0.113.7/32"}
	called := false
	life := configLifecycle{running: func() (bool, error) { called = true; return false, nil }}
	if _, err := changeConfig(profile, candidate, false, false, life); err == nil || called {
		t.Fatal("invalid candidate reached lifecycle")
	}
	if got, _ := readPolicy(profile); policyRevision(got) != policyRevision(base) {
		t.Fatal("invalid candidate replaced policy")
	}
	if _, err := os.Stat(filepath.Join(profile, "config-revisions")); !os.IsNotExist(err) {
		t.Fatal("invalid candidate created revisions")
	}
	path := filepath.Join(profile, "candidate.json")
	if err := securefile.Write(path, base); err != nil {
		t.Fatal(err)
	}
	unlock, err := securefile.Lock(filepath.Join(profile, "launch.lock"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := (CLI{}).Run([]string{"config", "apply", "--file", path, "--profile", profile}); err == nil {
		t.Fatal("apply ignored concurrent launch lock")
	}
}

func TestConfigRepairPreservesOriginalAcrossRepeatedFailure(t *testing.T) {
	for _, mode := range []string{"active", "stop", "start", "cleanup", "success"} {
		t.Run(mode, func(t *testing.T) {
			profile, base, candidate := versionFixture(t)
			for _, cfg := range []policy.Config{base, candidate} {
				if _, err := saveRevision(profile, cfg); err != nil {
					t.Fatal(err)
				}
			}
			tx := configTransaction{Version: 1, Phase: "recovery_required", From: policyRevision(base), To: policyRevision(candidate), Before: configHead{Version: 1, Current: policyRevision(base)}, Restart: true, Created: time.Now()}
			if err := securefile.Write(filepath.Join(profile, "config-transaction.json"), tx); err != nil {
				t.Fatal(err)
			}
			if err := securefile.Write(filepath.Join(profile, "policy.json"), candidate); err != nil {
				t.Fatal(err)
			}
			stops, starts := 0, 0
			life := configLifecycle{
				running: func() (bool, error) { return true, nil },
				stop: func() error {
					stops++
					if mode == "stop" || (mode == "cleanup" && stops == 2) {
						return errors.New("fixture recovery failed")
					}
					return nil
				},
				start: func(cfg policy.Config, _ []policy.Node) error {
					starts++
					pending, err := readConfigTransaction(profile)
					if err != nil || !pending.pending() || pending.From != policyRevision(base) || policyRevision(cfg) != policyRevision(base) {
						t.Fatal("original baseline lost before startup", err)
					}
					if mode != "success" {
						return errors.New("fixture restart failed")
					}
					return nil
				},
			}
			_, err := changeConfig(profile, base, mode != "active", true, life)
			if (err == nil) != (mode == "success") {
				t.Fatal(mode, err)
			}
			got, err := readPolicy(profile)
			if err != nil {
				t.Fatal(err)
			}
			after, err := readConfigTransaction(profile)
			if err != nil || after.From != tx.From || after.Before != tx.Before {
				t.Fatal("original journal lost", err)
			}
			if mode == "active" || mode == "stop" {
				if policyRevision(got) != tx.To || !after.pending() || starts != 0 {
					t.Fatal("unsafe recovery modified policy")
				}
			} else if policyRevision(got) != tx.From || starts != 1 || after.pending() != (mode == "cleanup") {
				t.Fatal("repair resurrected candidate or cleared failed recovery", after)
			}
			if mode == "active" && stops != 0 {
				t.Fatal("plain rollback changed network")
			}
		})
	}
}
