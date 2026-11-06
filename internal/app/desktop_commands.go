package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"netlaunch/internal/engine"
	"netlaunch/internal/policy"
	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/securefile"
	"netlaunch/internal/subscription"
)

// DesktopCommands is a user-context facade, not a privileged RPC dispatcher.
// Profile and Runtime are resolved by trusted host code, never renderer params.
// Service hosts must use a real user process/token context for this facade;
// thread impersonation does not change legacy process-token ownership checks.
type DesktopCommands struct{ Profile, Runtime string }

func (d DesktopCommands) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !filepath.IsAbs(d.Profile) || filepath.Clean(d.Profile) != d.Profile {
		return errors.New("workspace profile unavailable")
	}
	return nil
}

func (d DesktopCommands) Document(ctx context.Context) (any, error) {
	if err := d.check(ctx); err != nil {
		return nil, err
	}
	cfg, err := readPolicyForStorage(d.Profile)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{"configured": false}, nil
	}
	if err != nil {
		return nil, err
	}
	_, present, sourceErr := sourceConfigForStorage(d.Profile, cfg)
	return map[string]any{"configured": true, "policy": cfg, "revision": policyRevision(cfg),
		"sources": map[string]any{"present": present, "valid": sourceErr == nil, "values_redacted": true}}, nil
}

func (d DesktopCommands) Initialize(ctx context.Context, policyJSON, bootstrapJSON []byte) (any, error) {
	if err := d.check(ctx); err != nil {
		return nil, err
	}
	if (len(policyJSON) == 0) == (len(bootstrapJSON) == 0) {
		return nil, errors.New("provide exactly one policy or bootstrap document")
	}
	var cfg policy.Config
	var sources *subscription.Sources
	var err error
	if len(bootstrapJSON) > 0 {
		b, e := subscription.DecodeForStorage(bootstrapJSON, d.Profile)
		if e != nil {
			return nil, e
		}
		if err := desktopSourceBoundary(b.Subscriptions); err != nil {
			return nil, err
		}
		cfg, sources = b.Policy, &b.Subscriptions
	} else {
		cfg, err = policy.DecodeForStorage(policyJSON)
		if err != nil {
			return nil, err
		}
	}
	if err := securefile.Dir(d.Profile); err != nil {
		return nil, err
	}
	unlock, err := securefile.Lock(filepath.Join(d.Profile, "init.lock"), time.Second)
	if err != nil {
		return nil, err
	}
	defer unlock()
	for _, name := range []string{"policy.json", "sources.json", "nodes.json", "subscription-cache.json"} {
		if _, err := os.Lstat(filepath.Join(d.Profile, name)); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("profile already contains configuration")
		}
	}
	if sources != nil {
		if err = securefile.Write(filepath.Join(d.Profile, "sources.json"), sources); err != nil {
			return nil, err
		}
	}
	if err = securefile.Write(filepath.Join(d.Profile, "policy.json"), cfg); err != nil {
		if sources != nil {
			_ = os.Remove(filepath.Join(d.Profile, "sources.json"))
		}
		return nil, err
	}
	return map[string]any{"initialized": true, "revision": policyRevision(cfg), "company": false, "personal": false, "auto_connect": false}, nil
}

func (d DesktopCommands) ValidateDraft(ctx context.Context, raw []byte) (any, error) {
	if err := d.check(ctx); err != nil {
		return nil, err
	}
	cfg, err := policy.DecodeForStorage(raw)
	if err != nil {
		return nil, err
	}
	return map[string]any{"valid": true, "scope": "stored_policy", "revision": policyRevision(cfg), "runtime_prerequisites_checked": false}, nil
}

func (d DesktopCommands) DiffDraft(ctx context.Context, raw []byte) (any, error) {
	if err := d.check(ctx); err != nil {
		return nil, err
	}
	candidate, err := policy.DecodeForStorage(raw)
	if err != nil {
		return nil, err
	}
	before, err := readPolicyForStorage(d.Profile)
	if err != nil {
		return nil, err
	}
	return map[string]any{"from_revision": policyRevision(before), "to_revision": policyRevision(candidate), "changes": diffPolicy(before, candidate), "network_changes": false}, nil
}

func (d DesktopCommands) ApplyDraft(ctx context.Context, raw []byte, expectedRevision string) (any, error) {
	if err := d.check(ctx); err != nil {
		return nil, err
	}
	candidate, err := policy.DecodeForStorage(raw)
	if err != nil {
		return nil, err
	}
	return d.apply(ctx, candidate, expectedRevision, false)
}

func (d DesktopCommands) apply(ctx context.Context, candidate policy.Config, expected string, repair bool) (any, error) {
	if !validRevision(expected) {
		return nil, errors.New("expected policy revision is required")
	}
	unlock, err := securefile.Lock(filepath.Join(d.Profile, "launch.lock"), time.Second)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	before, err := readPolicyForStorage(d.Profile)
	if err != nil {
		return nil, err
	}
	if policyRevision(before) != expected {
		return nil, errors.New("policy revision changed; refresh the draft")
	}
	intent := desktopStorageIntent()
	life := configLifecycle{intent: &intent, storage: true, running: func() (bool, error) { return profileRunning(options{profile: d.Profile}) }}
	return changeConfig(d.Profile, candidate, false, repair, life)
}

func (d DesktopCommands) Rollback(ctx context.Context, revision, expectedRevision string) (any, error) {
	if err := d.check(ctx); err != nil {
		return nil, err
	}
	cfg, err := readRevisionForIntent(d.Profile, revision, desktopStorageIntent(), true)
	if err != nil {
		return nil, err
	}
	return d.apply(ctx, cfg, expectedRevision, true)
}

func (d DesktopCommands) History(ctx context.Context) (any, error) {
	if err := d.check(ctx); err != nil {
		return nil, err
	}
	head, err := readConfigHead(d.Profile)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(d.Profile, "config-revisions"))
	if errors.Is(err, os.ErrNotExist) {
		entries = nil
	} else if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		if !validRevision(id) {
			continue
		}
		if _, err := readRevisionForIntent(d.Profile, id, desktopStorageIntent(), true); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return map[string]any{"current_revision": head.Current, "previous_revision": head.Previous, "revisions": ids}, nil
}

func (d DesktopCommands) ImportNodes(ctx context.Context, content []byte) (any, error) {
	if err := d.check(ctx); err != nil {
		return nil, err
	}
	if len(content) == 0 || len(content) > 4<<20 {
		return nil, errors.New("node import must contain at most 4 MiB")
	}
	unlock, err := securefile.Lock(filepath.Join(d.Profile, "launch.lock"), time.Second)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err = requireCompleteConfigTransaction(d.Profile); err != nil {
		return nil, err
	}
	cfg, err := readPolicyForStorage(d.Profile)
	if err != nil {
		return nil, err
	}
	if _, present, err := sourceConfigForStorage(d.Profile, cfg); err != nil {
		return nil, err
	} else if present {
		return nil, errors.New("subscriptions configured; refresh them instead")
	}
	nodes, issues, err := policy.ImportSupportedNodes(content)
	if err != nil {
		return nil, err
	}
	if err = policy.ValidateEndpointsForStorage(cfg, nodes); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = securefile.Write(filepath.Join(d.Profile, "nodes.json"), nodes); err != nil {
		return nil, err
	}
	return map[string]any{"imported": len(nodes), "skipped": len(issues), "network_changes": false}, nil
}

func (d DesktopCommands) SyncSubscriptions(ctx context.Context) (any, error) {
	if err := d.check(ctx); err != nil {
		return nil, err
	}
	unlock, err := securefile.Lock(filepath.Join(d.Profile, "launch.lock"), time.Second)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err = requireCompleteConfigTransaction(d.Profile); err != nil {
		return nil, err
	}
	cfg, err := readPolicyForStorage(d.Profile)
	if err != nil {
		return nil, err
	}
	if err = syncSubscriptionsForStorage(ctx, d.Profile, cfg); err != nil {
		return nil, err
	}
	return map[string]any{"updated": true, "applies_to": "next_start"}, nil
}

// Desktop imports carry bounded content, not arbitrary local subscription paths.
// Legacy CLI file sources remain available outside this service protocol.
func desktopSourceBoundary(s subscription.Sources) error {
	all := append([]subscription.Source{s.Nodes}, s.Rules...)
	for _, source := range all {
		if source.File != "" {
			return errors.New("use a bounded file import instead of a subscription file path")
		}
	}
	return nil
}

func (d DesktopCommands) SaveSources(ctx context.Context, raw []byte, expectedRevision string) (any, error) {
	if err := d.check(ctx); err != nil {
		return nil, err
	}
	unlock, err := securefile.Lock(filepath.Join(d.Profile, "launch.lock"), time.Second)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err = requireCompleteConfigTransaction(d.Profile); err != nil {
		return nil, err
	}
	cfg, err := readPolicyForStorage(d.Profile)
	if err != nil {
		return nil, err
	}
	if !validRevision(expectedRevision) || policyRevision(cfg) != expectedRevision {
		return nil, errors.New("policy revision changed; refresh before editing sources")
	}
	envelope, err := json.Marshal(map[string]any{"version": 1, "policy": cfg, "subscriptions": json.RawMessage(raw)})
	if err != nil {
		return nil, errors.New("invalid sources document")
	}
	b, err := subscription.DecodeForStorage(envelope, d.Profile)
	if err != nil {
		return nil, err
	}
	if err = desktopSourceBoundary(b.Subscriptions); err != nil {
		return nil, err
	}
	if err = securefile.Write(filepath.Join(d.Profile, "sources.json"), b.Subscriptions); err != nil {
		return nil, err
	}
	return map[string]any{"saved": true, "cache_refresh_required": true, "values_redacted": true}, nil
}

func (d DesktopCommands) Explain(ctx context.Context, target string) (any, error) {
	if err := d.check(ctx); err != nil {
		return nil, err
	}
	cfg, err := readPolicyForStorage(d.Profile)
	if err != nil {
		return nil, err
	}
	plan, err := policy.RulePlanForStorage(cfg)
	if err != nil {
		return nil, err
	}
	explanation, err := policy.Explain(plan, target)
	if err != nil {
		return nil, err
	}
	return map[string]any{"scope": "saved_policy", "runtime_authorization": false, "explanation": explanation}, nil
}

func captureDesktopJSON(call func(CLI) error) (any, error) {
	var out bytes.Buffer
	if err := call(CLI{Out: &out, Err: io.Discard}); err != nil {
		return nil, err
	}
	if out.Len() > 1<<20 {
		return nil, errors.New("workspace response exceeds limit")
	}
	var value any
	decoder := json.NewDecoder(&out)
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("workspace response unavailable")
	}
	return value, nil
}

func (d DesktopCommands) Diagnostics(ctx context.Context) (any, error) {
	if err := d.check(ctx); err != nil {
		return nil, err
	}
	return captureDesktopJSON(func(cli CLI) error { return cli.diagnostics([]string{"export", "--profile", d.Profile}) })
}

func (d DesktopCommands) RuntimeCheck(ctx context.Context) (any, error) {
	if err := d.check(ctx); err != nil {
		return nil, err
	}
	return runtimebundle.Check(ctx, d.Runtime)
}

func (d DesktopCommands) Version(ctx context.Context) (any, error) {
	if err := d.check(ctx); err != nil {
		return nil, err
	}
	return currentBuildIdentity(), nil
}

func desktopRunPath(profile, id string) (string, error) {
	if !strings.HasPrefix(id, "netlaunch-") || len(id) != len("netlaunch-")+32 {
		return "", errors.New("invalid owned run identifier")
	}
	for _, ch := range strings.TrimPrefix(id, "netlaunch-") {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return "", errors.New("invalid owned run identifier")
		}
	}
	run := filepath.Join(profile, "runs", id)
	if err := engine.ValidateRun(run); err != nil {
		return "", err
	}
	return run, nil
}

func (d DesktopCommands) CleanupPreview(ctx context.Context) (any, error) {
	if err := d.check(ctx); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(d.Profile, "runs"))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{"runs": []any{}}, nil
	} else if err != nil {
		return nil, err
	}
	items := []any{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		run, err := desktopRunPath(d.Profile, e.Name())
		if err != nil {
			continue
		}
		preview, err := engine.CleanupRun(d.Profile, run, false)
		if err != nil {
			items = append(items, map[string]any{"run_id": e.Name(), "eligible": false})
			continue
		}
		items = append(items, map[string]any{"run_id": e.Name(), "preview": preview})
	}
	return map[string]any{"runs": items}, nil
}

func (d DesktopCommands) ApplyCleanup(ctx context.Context, id string) (any, error) {
	if err := d.check(ctx); err != nil {
		return nil, err
	}
	run, err := desktopRunPath(d.Profile, id)
	if err != nil {
		return nil, err
	}
	return engine.CleanupRun(d.Profile, run, true)
}
