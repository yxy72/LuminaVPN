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
	"sort"
	"time"

	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/subscription"
)

type subscriptionCache struct {
	Version     int                    `json:"version"`
	Fingerprint string                 `json:"fingerprint"`
	Updated     time.Time              `json:"updated"`
	Result      subscription.Result    `json:"result"`
	Snapshot    *subscription.Snapshot `json:"snapshot,omitempty"`
}

func sourceConfig(profile string) (subscription.Sources, bool, error) {
	cfg, e := readPolicy(profile)
	if e != nil {
		return subscription.Sources{}, false, e
	}
	return sourceConfigWithPolicy(profile, cfg)
}
func sourceConfigWithPolicy(profile string, cfg policy.Config) (subscription.Sources, bool, error) {
	path := filepath.Join(profile, "sources.json")
	if _, e := os.Lstat(path); errors.Is(e, os.ErrNotExist) {
		return subscription.Sources{}, false, nil
	}
	data, e := securefile.Read(path, 1<<20, true)
	if e != nil {
		return subscription.Sources{}, false, errors.New("private subscription sources unreadable")
	}
	// Reuse bootstrap validation, including URL and target restrictions.
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
	// Nine bounded sources can occupy 48 MiB after JSON base64 encoding, plus
	// parsed nodes/rules. Publish all of it atomically as one private envelope.
	raw, e := securefile.Read(filepath.Join(profile, "subscription-cache.json"), 64<<20, true)
	if e != nil || json.Unmarshal(raw, &cache) != nil {
		return cache, errors.New("no matching validated subscription cache; run sync")
	}
	switch cache.Version {
	case 1:
		// Legacy caches have no source bytes or independent source identity.
		// Never claim an edited policy matches them; one sync upgrades to v2.
		if cache.Fingerprint != fingerprint(cfg, s) {
			return cache, errors.New("legacy subscription cache requires one sync before offline policy edits")
		}
	case 2:
		if cache.Snapshot == nil {
			return cache, errors.New("subscription content missing; run sync")
		}
		fp, err := cache.Snapshot.Fingerprint(s)
		if err != nil {
			return cache, err
		}
		if cache.Fingerprint != fp {
			cache.Result, e = cache.Snapshot.Parse(s)
			if e != nil {
				return cache, e
			}
			cache.Fingerprint = fp
		}
	default:
		return cache, errors.New("unsupported subscription cache version; run sync")
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
	snapshot, result, e := subscription.FetchSnapshot(ctx, sources)
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
	fp, e := snapshot.Fingerprint(sources)
	if e != nil {
		return e
	}
	cache := subscriptionCache{Version: 2, Fingerprint: fp, Updated: time.Now(), Result: result, Snapshot: &snapshot}
	if e = securefile.Write(filepath.Join(o.profile, "subscription-cache.json"), cache); e != nil {
		return e
	}
	fmt.Fprintf(c.Out, "Updated private cache: %d nodes, %d personal rules; skipped %d nodes and %d unsupported/unmapped rules. Applies to the next start.\n", len(result.Nodes), len(result.Rules), result.SkippedNodes, result.SkippedRules)
	counts := map[string]int{}
	for _, issue := range result.Issues {
		counts[issue.Kind+":"+issue.Reason]++
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(c.Out, "Skipped %s: %d.\n", key, counts[key])
	}
	return nil
}
func effectiveProfile(profile string, cfg policy.Config) (policy.Config, []policy.Node, error) {
	s, present, e := sourceConfigWithPolicy(profile, cfg)
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
