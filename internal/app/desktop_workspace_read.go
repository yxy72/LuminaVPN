package app

// These explicit client readers accept stored configuration before runtime
// prerequisites are filled. They only read private local files and parse local
// snapshots; none of them fetches a source, writes a file or starts a worker.
import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/subscription"
)

func DesktopWorkspacePolicy(profile string) (policy.Config, error) {
	return readPolicyForStorage(profile)
}

func workspaceCache(profile string, cfg policy.Config, sources subscription.Sources) (subscriptionCache, error) {
	var cache subscriptionCache
	raw, err := securefile.Read(filepath.Join(profile, "subscription-cache.json"), 64<<20, true)
	if err != nil {
		return cache, errors.New("validated local subscription cache unavailable")
	}
	if json.Unmarshal(raw, &cache) != nil {
		return cache, errors.New("invalid local subscription cache")
	}
	switch cache.Version {
	case 1:
		if cache.Fingerprint != fingerprint(cfg, sources) {
			return cache, errors.New("legacy local cache requires refresh")
		}
	case 2:
		if cache.Snapshot == nil {
			return cache, errors.New("local subscription content missing")
		}
		fp, err := cache.Snapshot.Fingerprint(sources)
		if err != nil {
			return cache, errors.New("local subscription content identity invalid")
		}
		// Parse the saved source bytes, never a URL/file referenced by the source.
		result, err := cache.Snapshot.Parse(sources)
		if err != nil {
			return cache, errors.New("local subscription content invalid")
		}
		cache.Result, cache.Fingerprint = result, fp
	default:
		return cache, errors.New("unsupported local subscription cache")
	}
	if _, _, err := workspaceEffectiveResult(cfg, cache.Result); err != nil {
		return cache, err
	}
	return cache, nil
}

func workspaceEffectiveResult(cfg policy.Config, result subscription.Result) (policy.Config, []policy.Node, error) {
	cfg.PersonalRules = append(append([]policy.Rule{}, cfg.PersonalRules...), result.Rules...)
	if err := cfg.ValidateForStorage(); err != nil {
		return cfg, nil, errors.New("cached rules conflict with saved policy")
	}
	nodes := []policy.Node{}
	if len(result.Nodes) > 0 {
		var err error
		nodes, err = policy.SanitizeNodes(result.Nodes)
		if err != nil {
			return cfg, nil, errors.New("invalid local node inventory")
		}
	}
	if err := policy.ValidateEndpointsForStorage(cfg, nodes); err != nil {
		return cfg, nil, errors.New("local endpoints conflict with saved policy")
	}
	return cfg, nodes, nil
}

func DesktopWorkspaceNodes(profile string, cfg policy.Config) ([]policy.Node, error) {
	_, nodes, err := DesktopWorkspaceProfile(profile, cfg)
	return nodes, err
}

// DesktopWorkspaceProfile includes only validated cached subscription rules.
// Callers retain the saved base revision separately for compare-and-swap.
func DesktopWorkspaceProfile(profile string, cfg policy.Config) (policy.Config, []policy.Node, error) {
	sources, present, err := sourceConfigForStorage(profile, cfg)
	if err != nil {
		return cfg, nil, err
	}
	if present {
		if _, err := os.Lstat(filepath.Join(profile, "subscription-cache.json")); errors.Is(err, os.ErrNotExist) {
			return cfg, []policy.Node{}, nil
		}
		cache, err := workspaceCache(profile, cfg, sources)
		if err != nil {
			return cfg, nil, err
		}
		return workspaceEffectiveResult(cfg, cache.Result)
	}
	if _, err := os.Lstat(filepath.Join(profile, "nodes.json")); errors.Is(err, os.ErrNotExist) {
		return cfg, []policy.Node{}, nil
	}
	nodes, err := readNodes(profile)
	if err != nil {
		return cfg, nil, err
	}
	if err := policy.ValidateEndpointsForStorage(cfg, nodes); err != nil {
		return cfg, nil, errors.New("local endpoints conflict with saved policy")
	}
	return cfg, nodes, nil
}

func DesktopWorkspaceRules(profile string, cfg policy.Config) ([]policy.PlannedRule, error) {
	sources, present, err := sourceConfigForStorage(profile, cfg)
	if err != nil {
		return nil, err
	}
	if present {
		cache, err := workspaceCache(profile, cfg, sources)
		if err != nil {
			return nil, err
		}
		cfg, _, err = workspaceEffectiveResult(cfg, cache.Result)
		if err != nil {
			return nil, err
		}
	}
	return policy.RulePlanForStorage(cfg)
}

func DesktopWorkspaceSubscriptions(profile string, cfg policy.Config) (DesktopSubscription, error) {
	sources, present, err := sourceConfigForStorage(profile, cfg)
	result := DesktopSubscription{Configured: present}
	if err != nil || !present {
		return result, err
	}
	result.SourceCount = 1 + len(sources.Rules)
	result.SourceKinds = append(result.SourceKinds, "nodes")
	for range sources.Rules {
		result.SourceKinds = append(result.SourceKinds, "rules")
	}
	cache, err := workspaceCache(profile, cfg, sources)
	if err != nil {
		return result, nil
	}
	result.CacheAvailable, result.Updated = true, cache.Updated
	result.NodeCount, result.RuleCount = len(cache.Result.Nodes), len(cache.Result.Rules)
	return result, nil
}
