package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/subscription"
)

type subscriptionCache struct {
	Version     int                 `json:"version"`
	Fingerprint string              `json:"fingerprint"`
	Updated     time.Time           `json:"updated"`
	Result      subscription.Result `json:"result"`
}

func sourceConfig(profile string) (subscription.Sources, bool, error) {
	path := filepath.Join(profile, "sources.json")
	if _, e := os.Lstat(path); errors.Is(e, os.ErrNotExist) {
		return subscription.Sources{}, false, nil
	}
	data, e := securefile.Read(path, 1<<20, true)
	if e != nil {
		return subscription.Sources{}, false, errors.New("private subscription sources unreadable")
	}
	// Reuse bootstrap validation, including URL and target restrictions.
	cfg, e := readPolicy(profile)
	if e != nil {
		return subscription.Sources{}, false, e
	}
	raw, _ := json.Marshal(map[string]any{"version": 1, "policy": cfg, "subscriptions": json.RawMessage(data)})
	b, e := subscription.Decode(raw, profile)
	return b.Subscriptions, true, e
}
func fingerprint(cfg policy.Config, s subscription.Sources) string {
	raw, _ := json.Marshal(struct {
		Policy  policy.Config
		Sources subscription.Sources
	}{cfg, s})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func cachedSubscription(profile string, cfg policy.Config, s subscription.Sources) (subscriptionCache, error) {
	var cache subscriptionCache
	raw, e := securefile.Read(filepath.Join(profile, "subscription-cache.json"), 16<<20, true)
	if e != nil || json.Unmarshal(raw, &cache) != nil || cache.Version != 1 || cache.Fingerprint != fingerprint(cfg, s) {
		return cache, errors.New("no matching validated subscription cache; run sync")
	}
	if _, _, e = effectiveResult(cfg, cache.Result); e != nil {
		return cache, e
	}
	return cache, nil
}
func effectiveResult(cfg policy.Config, r subscription.Result) (policy.Config, []policy.Node, error) {
	cfg.PersonalRules = append(append([]policy.Rule{}, cfg.PersonalRules...), r.Rules...)
	if e := cfg.Validate(); e != nil {
		return cfg, nil, errors.New("subscription rules conflict with local policy")
	}
	nodes, e := policy.SanitizeNodes(r.Nodes)
	if e != nil {
		return cfg, nil, errors.New("invalid cached subscription nodes")
	}
	if e = policy.ValidateEndpoints(cfg, nodes); e != nil {
		return cfg, nil, errors.New("subscription endpoints conflict with local policy")
	}
	return cfg, nodes, nil
}
func (c CLI) syncSubscriptions(o options, cfg policy.Config, force bool) error {
	sources, present, e := sourceConfig(o.profile)
	if e != nil {
		return e
	}
	if !present {
		if force {
			return errors.New("no subscription sources configured")
		}
		return nil
	}
	unlock, e := securefile.Lock(filepath.Join(o.profile, "subscription.lock"), time.Second)
	if e != nil {
		return e
	}
	defer unlock()
	previous, cacheErr := cachedSubscription(o.profile, cfg, sources)
	if !force && cacheErr == nil && time.Since(previous.Updated) >= 0 && time.Since(previous.Updated) < time.Duration(sources.IntervalMinutes)*time.Minute {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	result, e := subscription.Fetch(ctx, sources)
	if e == nil {
		_, _, e = effectiveResult(cfg, result)
	}
	if e != nil {
		if !force && cacheErr == nil {
			fmt.Fprintln(c.Err, "Subscription update failed; using the previous validated local cache.")
			return nil
		}
		return errors.New("subscription update failed; previous cache retained, source details omitted")
	}
	cache := subscriptionCache{1, fingerprint(cfg, sources), time.Now(), result}
	if e = securefile.Write(filepath.Join(o.profile, "subscription-cache.json"), cache); e != nil {
		return e
	}
	fmt.Fprintf(c.Out, "Updated private cache: %d nodes, %d personal rules; skipped %d nodes and %d unsupported/unmapped rules. Applies to the next start.\n", len(result.Nodes), len(result.Rules), result.SkippedNodes, result.SkippedRules)
	return nil
}
func effectiveProfile(profile string, cfg policy.Config) (policy.Config, []policy.Node, error) {
	s, present, e := sourceConfig(profile)
	if e != nil {
		return cfg, nil, e
	}
	if present {
		cache, e := cachedSubscription(profile, cfg, s)
		if e != nil {
			return cfg, nil, e
		}
		return effectiveResult(cfg, cache.Result)
	}
	nodes, e := readNodes(profile)
	return cfg, nodes, e
}
