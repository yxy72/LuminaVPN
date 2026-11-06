package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
)

type configHead struct {
	Version  int    `json:"version"`
	Current  string `json:"current"`
	Previous string `json:"previous,omitempty"`
}
type configTransaction struct {
	Version int        `json:"version"`
	Phase   string     `json:"phase"`
	From    string     `json:"from"`
	To      string     `json:"to"`
	Before  configHead `json:"before"`
	Created time.Time  `json:"created"`
	Restart bool       `json:"restart"`
}

func (t configTransaction) pending() bool {
	return t.Version != 0 && t.Phase != "committed" && t.Phase != "rolled_back" && t.Phase != "aborted"
}

func policyRevision(cfg policy.Config) string {
	raw, _ := json.Marshal(cfg)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func validRevision(id string) bool {
	data, err := hex.DecodeString(id)
	return err == nil && len(data) == 32 && strings.ToLower(id) == id
}
func readRevision(profile, id string) (policy.Config, error) {
	return readRevisionForIntent(profile, id, policy.DefaultIntent())
}
func readRevisionForIntent(profile, id string, intent policy.ChannelIntent, storage ...bool) (policy.Config, error) {
	if !validRevision(id) {
		return policy.Config{}, errors.New("revision must be a full lowercase SHA-256 identifier")
	}
	raw, err := securefile.Read(filepath.Join(profile, "config-revisions", id+".json"), 1<<20, true)
	if err != nil {
		return policy.Config{}, errors.New("private configuration revision unavailable")
	}
	cfg, err := policy.DecodeForIntent(raw, intent)
	if len(storage) == 1 && storage[0] {
		cfg, err = policy.DecodeForStorage(raw)
	}
	if err != nil || policyRevision(cfg) != id {
		return policy.Config{}, errors.New("configuration revision failed validation or digest verification")
	}
	return cfg, nil
}
func saveRevision(profile string, cfg policy.Config) (string, error) {
	return saveRevisionForIntent(profile, cfg, policy.DefaultIntent())
}
func saveRevisionForIntent(profile string, cfg policy.Config, intent policy.ChannelIntent, storage ...bool) (string, error) {
	err := cfg.ValidateForIntent(intent)
	if len(storage) == 1 && storage[0] {
		err = cfg.ValidateForStorage()
	}
	if err != nil {
		return "", err
	}
	id := policyRevision(cfg)
	dir := filepath.Join(profile, "config-revisions")
	if err := securefile.Dir(dir); err != nil {
		return "", err
	}
	path := filepath.Join(dir, id+".json")
	if _, err := os.Lstat(path); err == nil {
		_, err = readRevisionForIntent(profile, id, intent, storage...)
		return id, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return id, securefile.Write(path, cfg)
}
func readConfigHead(profile string) (configHead, error) {
	var head configHead
	path := filepath.Join(profile, "config-head.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return head, nil
	}
	raw, err := securefile.Read(path, 4096, true)
	if err != nil || json.Unmarshal(raw, &head) != nil || head.Version != 1 || !validRevision(head.Current) || (head.Previous != "" && !validRevision(head.Previous)) {
		return head, errors.New("invalid private configuration revision pointer")
	}
	return head, nil
}
func readConfigTransaction(profile string) (configTransaction, error) {
	var tx configTransaction
	path := filepath.Join(profile, "config-transaction.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return tx, nil
	}
	raw, err := securefile.Read(path, 16384, true)
	if err != nil || json.Unmarshal(raw, &tx) != nil || tx.Version != 1 || !validRevision(tx.From) || !validRevision(tx.To) || tx.Before.Version != 1 || tx.Before.Current != tx.From || (tx.Before.Previous != "" && !validRevision(tx.Before.Previous)) {
		return tx, errors.New("invalid private configuration transaction; preserve revision files")
	}
	switch tx.Phase {
	case "prepared", "installed", "recovery_required", "committed", "rolled_back", "aborted":
		return tx, nil
	}
	return tx, errors.New("unknown configuration transaction phase")
}
func requireCompleteConfigTransaction(profile string) error {
	tx, err := readConfigTransaction(profile)
	if err != nil {
		return err
	}
	if tx.pending() {
		return errors.New("unfinished configuration change; run down if needed, then config rollback")
	}
	return nil
}
func ensurePolicyRevision(profile, expected string) error {
	return ensurePolicyRevisionForIntent(profile, expected, policy.DefaultIntent())
}
func ensurePolicyRevisionForIntent(profile, expected string, intent policy.ChannelIntent, storage ...bool) error {
	cfg, err := readPolicyForIntent(profile, intent)
	if len(storage) == 1 && storage[0] {
		cfg, err = readPolicyForStorage(profile)
	}
	if err != nil || policyRevision(cfg) != expected {
		return errors.New("policy changed outside this transaction; preserve revisions and inspect config history")
	}
	return nil
}

type configLifecycle struct {
	intent  *policy.ChannelIntent
	storage bool
	running func() (bool, error)
	stop    func() error
	start   func(policy.Config, []policy.Node) error
}

func lifecycleIntent(life configLifecycle) policy.ChannelIntent {
	if life.intent != nil {
		return *life.intent
	}
	return policy.DefaultIntent()
}

type configChangeResult struct {
	Revision        string `json:"revision"`
	Previous        string `json:"previous,omitempty"`
	AppliesTo       string `json:"applies_to"`
	RestartRequired bool   `json:"restart_required"`
}

// changeConfig is serialized by launch.lock. All snapshots contain policy only:
// no authentication, node secrets, VPN generations or native recovery state.
// restart failures restore the previous policy only after network cleanup.
func changeConfig(profile string, candidate policy.Config, restart, repair bool, life configLifecycle) (configChangeResult, error) {
	var out configChangeResult
	intent := lifecycleIntent(life)
	if err := validateLifecyclePolicy(candidate, life); err != nil {
		return out, err
	}
	tx, err := readConfigTransaction(profile)
	if err != nil {
		return out, err
	}
	if tx.pending() && !repair {
		return out, errors.New("unfinished configuration change; run config rollback first")
	}
	before, err := readLifecyclePolicy(profile, life)
	if err != nil {
		return out, err
	}
	from, to := policyRevision(before), policyRevision(candidate)
	if tx.pending() && from != tx.From && from != tx.To {
		return out, errors.New("pending configuration transaction conflicts with an external edit")
	}
	effective, nodes, err := effectiveLifecycleProfile(profile, candidate, life)
	if err != nil {
		return out, err
	}
	if err := validateLifecycleEndpoints(effective, nodes, life); err != nil {
		return out, err
	}
	running, err := life.running()
	if err != nil {
		return out, err
	}
	if restart && (life.start == nil || life.stop == nil) {
		return out, errors.New("configuration restart is unavailable")
	}
	if tx.pending() && repair {
		if running && !restart {
			return out, errors.New("unfinished configuration restart still owns a run; run down first or use config rollback --restart")
		}
		if to != tx.From {
			return out, errors.New("pending transaction must restore its original revision")
		}
		return repairConfigChange(profile, tx, from, candidate, effective, nodes, restart, running, life)
	}
	head, err := readConfigHead(profile)
	if err != nil {
		return out, err
	}
	if head.Current != from {
		head = configHead{Version: 1, Current: from, Previous: head.Current}
	}
	if _, err := saveRevisionForIntent(profile, before, intent, life.storage); err != nil {
		return out, err
	}
	if _, err := saveRevisionForIntent(profile, candidate, intent, life.storage); err != nil {
		return out, err
	}
	if err := securefile.Write(filepath.Join(profile, "config-head.json"), head); err != nil {
		return out, err
	}
	if from == to && !restart && !tx.pending() {
		return configChangeResult{Revision: to, Previous: head.Previous, AppliesTo: "unchanged", RestartRequired: running}, nil
	}
	tx = configTransaction{Version: 1, Phase: "prepared", From: from, To: to, Before: head, Created: time.Now(), Restart: restart}
	writeTx := func() error { return securefile.Write(filepath.Join(profile, "config-transaction.json"), tx) }
	if err := writeTx(); err != nil {
		return out, err
	}
	if restart {
		if err := life.stop(); err != nil {
			tx.Phase = "aborted"
			return out, errors.Join(errors.New("previous run recovery incomplete; policy was not changed"), err, writeTx())
		}
	}
	if err := ensurePolicyRevisionForIntent(profile, from, intent, life.storage); err != nil {
		return out, err
	}
	if err := securefile.Write(filepath.Join(profile, "policy.json"), candidate); err != nil {
		return out, err
	}
	tx.Phase = "installed"
	if err := writeTx(); err != nil {
		return out, err
	}
	if restart {
		if startErr := life.start(effective, nodes); startErr != nil {
			if cleanupErr := life.stop(); cleanupErr != nil {
				tx.Phase = "recovery_required"
				return out, errors.Join(errors.New("candidate startup and recovery failed; run down, then config rollback"), startErr, cleanupErr, writeTx())
			}
			if err := ensurePolicyRevisionForIntent(profile, to, intent, life.storage); err != nil {
				return out, errors.Join(startErr, err)
			}
			if err := securefile.Write(filepath.Join(profile, "policy.json"), before); err != nil {
				return out, errors.Join(startErr, err)
			}
			if err := securefile.Write(filepath.Join(profile, "config-head.json"), head); err != nil {
				return out, errors.Join(startErr, err)
			}
			tx.Phase = "rolled_back"
			return out, errors.Join(errors.New("candidate startup failed; previous policy restored and network stopped; inspect status before up"), startErr, writeTx())
		}
	}
	if err := ensurePolicyRevisionForIntent(profile, to, intent, life.storage); err != nil {
		return out, err
	}
	next := configHead{Version: 1, Current: to, Previous: from}
	if from == to {
		next.Previous = head.Previous
	}
	if err := securefile.Write(filepath.Join(profile, "config-head.json"), next); err != nil {
		return out, err
	}
	tx.Phase = "committed"
	if err := writeTx(); err != nil {
		return out, err
	}
	out = configChangeResult{Revision: to, Previous: next.Previous, AppliesTo: "next_start", RestartRequired: running}
	if restart {
		out.AppliesTo, out.RestartRequired = "running", false
	}
	return out, nil
}

func repairConfigChange(profile string, tx configTransaction, current string, original, effective policy.Config, nodes []policy.Node, restart, running bool, life configLifecycle) (configChangeResult, error) {
	out := configChangeResult{Revision: tx.From, Previous: tx.Before.Previous, AppliesTo: "next_start", RestartRequired: running}
	if restart {
		if err := life.stop(); err != nil {
			return out, err
		}
	}
	if err := ensurePolicyRevisionForIntent(profile, current, lifecycleIntent(life), life.storage); err != nil {
		return out, err
	}
	if err := securefile.Write(filepath.Join(profile, "policy.json"), original); err != nil {
		return out, err
	}
	if err := securefile.Write(filepath.Join(profile, "config-head.json"), tx.Before); err != nil {
		return out, err
	}
	tx.Phase = "rolled_back"
	if restart {
		// Keep the original baseline pending until the repaired run is ready.
		// A crash or second startup failure must never promote the failed candidate.
		tx.Phase = "installed"
	}
	if err := securefile.Write(filepath.Join(profile, "config-transaction.json"), tx); err != nil {
		return out, err
	}
	if restart {
		if err := life.start(effective, nodes); err != nil {
			cleanup := life.stop()
			tx.Phase = "rolled_back"
			if cleanup != nil {
				tx.Phase = "recovery_required"
			}
			cleanup = errors.Join(cleanup, securefile.Write(filepath.Join(profile, "config-transaction.json"), tx))
			return out, errors.Join(errors.New("original policy restored, but restart failed; inspect status and recovery before up"), err, cleanup)
		}
		tx.Phase = "rolled_back"
		if err := securefile.Write(filepath.Join(profile, "config-transaction.json"), tx); err != nil {
			return out, err
		}
		out.AppliesTo, out.RestartRequired = "running", false
	}
	return out, nil
}

func rollbackPolicy(profile, requested string) (policy.Config, error) {
	tx, err := readConfigTransaction(profile)
	if err != nil {
		return policy.Config{}, err
	}
	if tx.pending() {
		if requested != "" && requested != tx.From {
			return policy.Config{}, errors.New("unfinished transaction must first roll back to its previous revision")
		}
		return readRevision(profile, tx.From)
	}
	if requested == "" {
		head, err := readConfigHead(profile)
		if err != nil {
			return policy.Config{}, err
		}
		current, err := readPolicy(profile)
		if err != nil {
			return policy.Config{}, err
		}
		requested = head.Previous
		if head.Current != "" && head.Current != policyRevision(current) {
			requested = head.Current
		}
	}
	if requested == "" {
		return policy.Config{}, errors.New("no previous managed revision; use config history")
	}
	return readRevision(profile, requested)
}

func (c CLI) configHistory(profile string) error {
	head, err := readConfigHead(profile)
	if err != nil {
		return err
	}
	tx, err := readConfigTransaction(profile)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(profile, "config-revisions"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ids := []string{}
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") && validRevision(id) {
			ids = append(ids, id)
		}
	}
	return c.json(map[string]any{"current": head.Current, "previous": head.Previous, "revisions": ids, "transaction_pending": tx.pending()})
}

func configChangeError(command string, err error) error { return fmt.Errorf("%s: %w", command, err) }
