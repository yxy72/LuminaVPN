//go:build darwin

package engine

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/selector"
)

// This derivation keeps fake-IP mappings across reloads and owns fallback lease expiry.
func requireDarwinReloadCore(root string) error {
	const (
		version = "v1.19.32-lumina.3"
		digest  = "021ed3a3d46eee0433a42187d6c09fa5b51b1c20850e123fc5404310656d01df"
	)
	bundle, err := runtimebundle.Verify(root)
	if err != nil {
		return err
	}
	for _, file := range bundle.Files {
		if file.Path == "bin/mihomo" && file.SHA256 == digest && bundle.Mihomo == version {
			return nil
		}
	}
	return errors.New("macOS managed reload requires the reviewed fake-IP and fallback lease runtime")
}

func darwinReloadGroups(config map[string]any) map[string]string {
	first := make(map[string]string)
	groups, _ := config["proxy-groups"].([]any)
	for _, raw := range groups {
		group, _ := raw.(map[string]any)
		name, _ := group["name"].(string)
		if group["type"] != "select" || name == "" {
			continue
		}
		// A newly compiled config has []string. The previous on-disk config
		// is decoded through JSON and has []any.
		var target string
		switch choices := group["proxies"].(type) {
		case []string:
			if len(choices) != 0 {
				target = choices[0]
			}
		case []any:
			if len(choices) != 0 {
				target, _ = choices[0].(string)
			}
		}
		if _, exists := first[name]; exists {
			target = ""
		}
		first[name] = target
	}
	return first
}

func prepareDarwinPersonalConfig(config, previous map[string]any, path string, c desktopReloadControl) error {
	next, old := darwinReloadGroups(config), darwinReloadGroups(previous)
	for _, group := range []string{"PHYSICAL", "PERSONAL", "CORP"} {
		if next[group] != selector.Reject || old[group] != selector.Reject {
			return errors.New("macOS resolver reload requires closed-by-default egress groups")
		}
	}
	nextProfile, _ := config["profile"].(map[string]any)
	oldProfile, _ := previous["profile"].(map[string]any)
	nextDNS, _ := config["dns"].(map[string]any)
	oldDNS, _ := previous["dns"].(map[string]any)
	if nextProfile["store-selected"] != false || oldProfile["store-selected"] != false ||
		nextProfile["store-fake-ip"] != false || oldProfile["store-fake-ip"] != false ||
		nextDNS["enable"] != true || oldDNS["enable"] != true ||
		nextDNS["enhanced-mode"] != "fake-ip" || oldDNS["enhanced-mode"] != "fake-ip" ||
		nextDNS["fake-ip-range"] != "198.19.0.1/16" || oldDNS["fake-ip-range"] != "198.19.0.1/16" {
		return errors.New("macOS resolver reload requires the managed in-memory fake-IP pool")
	}
	nextCandidate, keepsCandidate := next[candidateGroup]
	if keepsCandidate && nextCandidate != selector.Reject {
		return errors.New("macOS candidate ingress would open during resolver reload")
	}
	candidate, hadCandidate := old[candidateGroup]
	if hadCandidate && candidate != selector.Reject {
		return errors.New("macOS candidate ingress is missing its closed default")
	}
	if err := gateDesktopConfig(c); err != nil {
		return err
	}
	if hadCandidate {
		if err := c.selectGroup(candidateGroup, selector.Reject); err != nil {
			return err
		}
	}
	if err := replaceGatedDesktopConfig(config, previous, path, c); err != nil {
		return err
	}
	if keepsCandidate {
		if err := c.selectGroup(candidateGroup, selector.Reject); err != nil {
			return err
		}
	}
	// Recheck after replacement to retire connections that became visible
	// while Mihomo was applying the control-plane reload.
	return closeDesktopEgress(previous, c)
}

func prepareDarwinPersonalReload(ctx context.Context, run string, before State, config map[string]any, authorize func(State) error) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		state, err := load(run)
		if err != nil {
			return err
		}
		if err := guard(run, &state); err != nil {
			return err
		}
		intent := currentIntent(state)
		if !state.TakeoverActive || state.RunSpecDigest != before.RunSpecDigest || state.Runner != before.Runner ||
			state.Manifest.Network != before.Manifest.Network || state.ChannelGeneration != before.ChannelGeneration ||
			state.AppliedGeneration != state.ChannelGeneration || state.AppliedChannels == nil || *state.AppliedChannels != intent ||
			intent != currentIntent(before) {
			return errors.New("macOS resolver reload no longer belongs to the active run")
		}
		if authorize != nil {
			return authorize(state)
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	var previous map[string]any
	if err := readCore(run, &previous); err != nil {
		return err
	}
	err := prepareDarwinPersonalConfig(config, previous, filepath.Join(private(run), "core.json"), desktopReloadControl{
		selectGroup: func(group, target string) error {
			if err := check(); err != nil {
				return err
			}
			return selectCoreGroupContext(ctx, run, group, target)
		},
		request: func(method, path string, payload, out any) error {
			if err := check(); err != nil {
				return err
			}
			return apiContext(ctx, run, method, path, payload, out)
		},
		save: func(config map[string]any) error {
			if err := check(); err != nil {
				return err
			}
			return saveCore(run, config)
		},
	})
	if err != nil {
		return errors.Join(err, closeDarwinBasePaths(ctx, run))
	}
	return nil
}

// Closing does not require a current intent. It is safe to tighten the gates
// of this root-owned run after STOP or a failed write of the status journal.
func closeDarwinBasePaths(ctx context.Context, run string) error {
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	return errors.Join(selectCoreGroupContext(closeCtx, run, "PHYSICAL", selector.Reject),
		selectCoreGroupContext(closeCtx, run, "PERSONAL", selector.Reject))
}

func openDarwinBasePaths(ctx context.Context, run string, before State, network platform.Network, intent policy.ChannelIntent) error {
	if live, err := platform.Discover(); err != nil || live != network {
		return errors.New("macOS physical network changed during egress preparation")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	attempted := false
	err := update(run, func(s *State) error {
		if err := guard(run, s); err != nil {
			return err
		}
		if s.Manifest.Mode == "" || s.RunSpecDigest != before.RunSpecDigest || s.Runner != before.Runner ||
			s.Manifest.Network != network || s.Manifest.Binding.Physical != network.Interface ||
			s.ChannelGeneration != before.ChannelGeneration || currentIntent(*s) != intent ||
			s.TakeoverActive && (s.AppliedGeneration != s.ChannelGeneration || s.AppliedChannels == nil || *s.AppliedChannels != intent) {
			return errors.New("macOS egress no longer belongs to the active network generation")
		}
		if err := requireActiveDarwinOwner(run, *s); err != nil {
			return err
		}
		attempted = true
		if err := openDesktopConfig(func(group, target string) error {
			if err := guard(run, s); err != nil {
				return err
			}
			return selectCoreGroupContext(ctx, run, group, target)
		}, !intent.Personal); err != nil {
			return err
		}
		if err := guard(run, s); err != nil {
			return err
		}
		if !intent.Personal {
			s.Personal = "PHYSICAL"
		}
		return nil
	})
	if err == nil || !attempted {
		return err
	}
	// A failed readback or state write may follow a successful controller
	// mutation. Make a bounded effort to restore both gates before recovery.
	return errors.Join(err, closeDarwinBasePaths(ctx, run))
}
