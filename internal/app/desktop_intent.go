package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/subscription"
)

// Storage validation does not authorize running either channel. Runtime start
// validates the explicit desired channels separately, without invented VPN data.
func desktopStorageIntent() policy.ChannelIntent { return policy.ChannelIntent{} }

func readPolicyForStorage(profile string) (policy.Config, error) {
	raw, err := securefile.Read(filepath.Join(profile, "policy.json"), 1<<20, true)
	if err != nil {
		return policy.Config{}, err
	}
	return policy.DecodeForStorage(raw)
}

func validateLifecyclePolicy(cfg policy.Config, life configLifecycle) error {
	if life.storage {
		return cfg.ValidateForStorage()
	}
	return cfg.ValidateForIntent(lifecycleIntent(life))
}
func readLifecyclePolicy(profile string, life configLifecycle) (policy.Config, error) {
	if life.storage {
		return readPolicyForStorage(profile)
	}
	return readPolicyForIntent(profile, lifecycleIntent(life))
}
func effectiveLifecycleProfile(profile string, cfg policy.Config, life configLifecycle) (policy.Config, []policy.Node, error) {
	if life.storage {
		return cfg, nil, cfg.ValidateForStorage()
	}
	return effectiveProfileForIntent(profile, cfg, lifecycleIntent(life))
}
func validateLifecycleEndpoints(cfg policy.Config, nodes []policy.Node, life configLifecycle) error {
	if life.storage {
		return cfg.ValidateForStorage()
	}
	return policy.ValidateEndpointsForIntent(cfg, nodes, lifecycleIntent(life))
}

func sourceConfigForStorage(profile string, cfg policy.Config) (subscription.Sources, bool, error) {
	path := filepath.Join(profile, "sources.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return subscription.Sources{}, false, nil
	} else if err != nil {
		return subscription.Sources{}, false, errors.New("source metadata unavailable")
	}
	raw, err := securefile.Read(path, 1<<20, true)
	if err != nil {
		return subscription.Sources{}, false, errors.New("private source metadata unavailable")
	}
	envelope, err := json.Marshal(map[string]any{"version": 1, "policy": cfg, "subscriptions": json.RawMessage(raw)})
	if err != nil {
		return subscription.Sources{}, false, errors.New("invalid source metadata")
	}
	b, err := subscription.DecodeForStorage(envelope, profile)
	return b.Subscriptions, true, err
}

func readPolicyForIntent(profile string, intent policy.ChannelIntent) (policy.Config, error) {
	if intent == policy.DefaultIntent() {
		return readPolicy(profile)
	}
	raw, err := securefile.Read(filepath.Join(profile, "policy.json"), 1<<20, true)
	if err != nil {
		return policy.Config{}, err
	}
	return policy.DecodeForIntent(raw, intent)
}

func sourceConfigForIntent(profile string, cfg policy.Config, intent policy.ChannelIntent) (subscription.Sources, bool, error) {
	path := filepath.Join(profile, "sources.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return subscription.Sources{}, false, nil
	} else if err != nil {
		return subscription.Sources{}, false, errors.New("subscription source metadata unavailable")
	}
	raw, err := securefile.Read(path, 1<<20, true)
	if err != nil {
		return subscription.Sources{}, false, errors.New("private subscription sources unreadable")
	}
	envelope, err := json.Marshal(map[string]any{"version": 1, "policy": cfg, "subscriptions": json.RawMessage(raw)})
	if err != nil {
		return subscription.Sources{}, false, errors.New("subscription source metadata invalid")
	}
	b, err := subscription.DecodeForIntent(envelope, profile, intent)
	return b.Subscriptions, true, err
}

func effectiveResultForIntent(cfg policy.Config, result subscription.Result, intent policy.ChannelIntent) (policy.Config, []policy.Node, error) {
	if intent == policy.DefaultIntent() {
		return effectiveResult(cfg, result)
	}
	cfg.PersonalRules = append(append([]policy.Rule{}, cfg.PersonalRules...), result.Rules...)
	if err := cfg.ValidateForIntent(intent); err != nil {
		return cfg, nil, errors.New("subscription rules conflict with local policy")
	}
	nodes, err := policy.SanitizeNodes(result.Nodes)
	if err != nil {
		return cfg, nil, errors.New("invalid cached subscription nodes")
	}
	if err := policy.ValidateEndpointsForIntent(cfg, nodes, intent); err != nil {
		return cfg, nil, err
	}
	return cfg, nodes, nil
}

func effectiveResultForStorage(cfg policy.Config, result subscription.Result) (policy.Config, []policy.Node, error) {
	cfg.PersonalRules = append(append([]policy.Rule{}, cfg.PersonalRules...), result.Rules...)
	if err := cfg.ValidateForStorage(); err != nil {
		return cfg, nil, errors.New("subscription rules conflict with local policy")
	}
	nodes, err := policy.SanitizeNodes(result.Nodes)
	if err != nil {
		return cfg, nil, errors.New("invalid cached subscription nodes")
	}
	if err = policy.ValidateEndpointsForStorage(cfg, nodes); err != nil {
		return cfg, nil, err
	}
	return cfg, nodes, nil
}

func effectiveProfileForIntent(profile string, cfg policy.Config, intent policy.ChannelIntent) (policy.Config, []policy.Node, error) {
	if intent == policy.DefaultIntent() {
		return effectiveProfile(profile, cfg)
	}
	if !intent.Personal {
		return cfg, nil, cfg.ValidateForIntent(intent)
	}
	sources, present, err := sourceConfigForIntent(profile, cfg, intent)
	if err != nil {
		return cfg, nil, err
	}
	if !present {
		nodes, err := readNodes(profile)
		return cfg, nodes, err
	}
	var cache subscriptionCache
	raw, err := securefile.Read(filepath.Join(profile, "subscription-cache.json"), 64<<20, true)
	if err != nil || json.Unmarshal(raw, &cache) != nil {
		return cfg, nil, errors.New("no validated subscription cache; refresh the configured sources")
	}
	switch cache.Version {
	case 1:
		if cache.Fingerprint != fingerprint(cfg, sources) {
			return cfg, nil, errors.New("legacy subscription cache needs refresh")
		}
	case 2:
		if cache.Snapshot == nil {
			return cfg, nil, errors.New("subscription content missing")
		}
		fp, err := cache.Snapshot.Fingerprint(sources)
		if err != nil {
			return cfg, nil, err
		}
		if cache.Fingerprint != fp {
			cache.Result, err = cache.Snapshot.Parse(sources)
			if err != nil {
				return cfg, nil, err
			}
		}
	default:
		return cfg, nil, errors.New("unsupported subscription cache version")
	}
	return effectiveResultForIntent(cfg, cache.Result, intent)
}
