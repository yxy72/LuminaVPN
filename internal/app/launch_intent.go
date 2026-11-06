package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/subscription"
)

func launchIntent(o options) policy.ChannelIntent {
	if o.channels != nil {
		return *o.channels
	}
	return policy.DefaultIntent()
}

func readLaunchPolicy(o options) (policy.Config, error) {
	if o.mode == "" {
		return readPolicy(o.profile)
	}
	return readPolicyForIntent(o.profile, launchIntent(o))
}

func effectiveLaunchProfile(o options, cfg policy.Config) (policy.Config, []policy.Node, error) {
	if o.mode == "" {
		return effectiveProfile(o.profile, cfg)
	}
	return effectiveProfileForIntent(o.profile, cfg, launchIntent(o))
}

// No implicit refresh is performed for a disabled personal channel. The caller's
// operation context owns refresh cancellation; GUI read timeouts do not own it.
func syncSubscriptionsForIntent(ctx context.Context, profile string, cfg policy.Config, intent policy.ChannelIntent, force bool) error {
	return syncSubscriptionsWith(ctx, profile, cfg, intent, force, false, subscription.FetchSnapshot)
}

func syncSubscriptionsForStorage(ctx context.Context, profile string, cfg policy.Config) error {
	return syncSubscriptionsWith(ctx, profile, cfg, desktopStorageIntent(), true, true, subscription.FetchSnapshot)
}

func syncSubscriptionsWith(ctx context.Context, profile string, cfg policy.Config, intent policy.ChannelIntent, force, storage bool, fetch func(context.Context, subscription.Sources) (subscription.Snapshot, subscription.Result, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var sources subscription.Sources
	var present bool
	var err error
	if storage {
		sources, present, err = sourceConfigForStorage(profile, cfg)
	} else {
		sources, present, err = sourceConfigForIntent(profile, cfg, intent)
	}
	if err != nil {
		return err
	}
	if storage && present {
		if err := desktopSourceBoundary(sources); err != nil {
			return err
		}
	}
	if !present {
		if force {
			return errors.New("no subscription sources configured")
		}
		return nil
	}
	unlock, err := securefile.Lock(filepath.Join(profile, "subscription.lock"), time.Second)
	if err != nil {
		return err
	}
	defer unlock()
	if !force {
		var previous subscriptionCache
		raw, readErr := securefile.Read(filepath.Join(profile, "subscription-cache.json"), 64<<20, true)
		if readErr == nil && json.Unmarshal(raw, &previous) == nil {
			age := time.Since(previous.Updated)
			if age >= 0 && age < time.Duration(sources.IntervalMinutes)*time.Minute {
				if _, _, err := effectiveProfileForIntent(profile, cfg, intent); err == nil {
					return nil
				}
			}
		}
	}
	bounded, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	snapshot, result, err := fetch(bounded, sources)
	if err != nil {
		return errors.New("subscription refresh failed; previous cache retained")
	}
	if storage {
		_, _, err = effectiveResultForStorage(cfg, result)
	} else {
		_, _, err = effectiveResultForIntent(cfg, result, intent)
	}
	if err != nil {
		return err
	}
	fingerprint, err := snapshot.Fingerprint(sources)
	if err != nil {
		return err
	}
	if err := bounded.Err(); err != nil {
		return err
	}
	return securefile.Write(filepath.Join(profile, "subscription-cache.json"), subscriptionCache{
		Version: 2, Fingerprint: fingerprint, Updated: time.Now(), Result: result, Snapshot: &snapshot,
	})
}

func diagnoseLaunch(o options, cfg policy.Config) ([]string, []platform.PortCheck) {
	if o.mode == "" {
		return diagnose(o, cfg)
	}
	// The same preflight is retained, but an intentionally disabled company
	// channel does not acquire authentication prerequisites as a side effect.
	copy := cfg
	if !launchIntent(o).Company {
		copy.VPN.Server, copy.VPN.EndpointIPv4 = "", ""
	}
	return diagnose(o, copy)
}

// A nil cache is legal only when the personal channel is disabled. Corrupt or
// inaccessible files are never silently interpreted as an empty candidate set.
func desktopNodesIfPresent(profile string) ([]policy.Node, bool, error) {
	if _, err := os.Lstat(filepath.Join(profile, "nodes.json")); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, errors.New("node metadata unavailable")
	}
	nodes, err := readNodes(profile)
	return nodes, true, err
}
