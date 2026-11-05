package app

// These read-only entry points share the CLI's validated profile, cache and
// saved-state readers. They do not download, lock, initialize or launch.
import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"netlaunch/internal/engine"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
)

type DesktopBuildIdentity = buildIdentity

func DesktopBuild() DesktopBuildIdentity { return currentBuildIdentity() }

func DesktopPolicy(profile string) (policy.Config, error) { return readPolicy(profile) }

func DesktopNodes(profile string, cfg policy.Config) ([]policy.Node, error) {
	_, nodes, err := effectiveProfile(profile, cfg)
	return nodes, err
}

func DesktopRules(profile string, cfg policy.Config) ([]policy.PlannedRule, error) {
	return effectiveRulePlan(profile, cfg)
}

func DesktopRevision(cfg policy.Config) string { return policyRevision(cfg) }

func DesktopTransactionPending(profile string) (bool, error) {
	tx, err := readConfigTransaction(profile)
	return tx.pending() || err != nil, err
}

// An unreadable or invalid pointer means a run may exist. It must never be
// treated as proof that a previous start had no effect.
func DesktopSavedStatus(profile string) (run string, status engine.Status, present, stop bool, err error) {
	path := filepath.Join(profile, "current.json")
	if _, e := os.Lstat(path); errors.Is(e, os.ErrNotExist) {
		return "", status, false, false, nil
	}
	present = true
	raw, e := securefile.Read(path, 4096, true)
	if e != nil {
		return "", status, present, false, e
	}
	var ref struct {
		Run string `json:"run"`
	}
	if json.Unmarshal(raw, &ref) != nil || engine.ValidateRun(ref.Run) != nil {
		return "", status, present, false, errors.New("saved run reference unavailable")
	}
	run = ref.Run
	if _, e := os.Lstat(filepath.Join(run, "STOP")); e == nil {
		stop = true
	}
	status, err = statusFor(run)
	return
}

type DesktopSubscription struct {
	Configured     bool
	SourceCount    int
	SourceKinds    []string
	CacheAvailable bool
	Updated        time.Time
	NodeCount      int
	RuleCount      int
}

func DesktopSubscriptions(profile string, cfg policy.Config) (DesktopSubscription, error) {
	sources, present, err := sourceConfigWithPolicy(profile, cfg)
	result := DesktopSubscription{Configured: present}
	if err != nil || !present {
		return result, err
	}
	result.SourceCount = 1 + len(sources.Rules)
	result.SourceKinds = append(result.SourceKinds, "nodes")
	for range sources.Rules {
		result.SourceKinds = append(result.SourceKinds, "rules")
	}
	cache, err := cachedSubscription(profile, cfg, sources)
	if err != nil {
		return result, nil
	}
	result.CacheAvailable, result.Updated = true, cache.Updated
	result.NodeCount, result.RuleCount = len(cache.Result.Nodes), len(cache.Result.Rules)
	return result, nil
}
