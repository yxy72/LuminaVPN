package app

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
)

func (c CLI) maintenance(args []string) error {
	if len(args) < 2 {
		return errors.New("use config validate|diff|apply|rollback|history or rules explain TARGET")
	}
	command := args[0] + " " + args[1]
	if args[0] == "config" {
		switch args[1] {
		case "diff", "apply", "rollback", "history":
			return c.configMaintenance(args)
		}
	}
	if command != "config validate" && command != "rules explain" {
		return errors.New("unknown configuration command")
	}
	rest := args[2:]
	target := ""
	if command == "rules explain" {
		if len(rest) == 0 {
			return errors.New("rules explain requires a hostname or IPv4 address before options")
		}
		target, rest = rest[0], rest[1:]
	}
	profile, err := DefaultProfile()
	if err != nil {
		return err
	}
	file := ""
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(c.Err)
	fs.StringVar(&profile, "profile", profile, "private local profile directory")
	fs.StringVar(&file, "file", "", "candidate policy JSON; current profile is unchanged")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected configuration arguments")
	}
	profile, err = filepath.Abs(profile)
	if err != nil {
		return err
	}
	var cfg policy.Config
	if file == "" {
		cfg, err = readPolicy(profile)
	} else {
		file, err = filepath.Abs(file)
		if err != nil {
			return err
		}
		raw, readErr := securefile.Read(file, 1<<20, false)
		if readErr != nil {
			return errors.New("candidate policy is not a readable bounded regular file")
		}
		cfg, err = policy.Decode(raw)
	}
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	if command == "config validate" {
		return c.validateOffline(profile, cfg)
	}
	plan, err := effectiveRulePlan(profile, cfg)
	if err != nil {
		return err
	}
	explanation, err := policy.Explain(plan, target)
	if err != nil {
		return err
	}
	return c.json(explanation)
}

func (c CLI) validateOffline(profile string, cfg policy.Config) error {
	_, present, err := sourceConfigWithPolicy(profile, cfg)
	if err != nil {
		return err
	}
	cacheName := "nodes.json"
	if present {
		cacheName = "subscription-cache.json"
	}
	if _, err := os.Lstat(filepath.Join(profile, cacheName)); errors.Is(err, os.ErrNotExist) {
		return c.json(map[string]any{"valid": true, "scope": "policy_only", "nodes_checked": false, "warnings": []string{"Node cache is missing; endpoint compatibility has not been checked."}})
	} else if err != nil {
		return errors.New("local node cache cannot be inspected")
	}
	effective, nodes, err := effectiveProfile(profile, cfg)
	if err != nil {
		return err
	}
	if err := policy.ValidateEndpoints(effective, nodes); err != nil {
		return err
	}
	return c.json(map[string]any{"valid": true, "scope": "effective_policy", "nodes_checked": true, "node_count": len(nodes), "personal_rule_count": len(effective.PersonalRules)})
}

func effectiveRulePlan(profile string, cfg policy.Config) ([]policy.PlannedRule, error) {
	sources, present, err := sourceConfigWithPolicy(profile, cfg)
	if err != nil {
		return nil, err
	}
	if !present {
		return policy.RulePlan(cfg)
	}
	cache, err := cachedSubscription(profile, cfg, sources)
	if err != nil {
		return nil, err
	}
	effective, _, err := effectiveResult(cfg, cache.Result)
	if err != nil {
		return nil, err
	}
	plan, err := policy.RulePlan(effective)
	if err != nil {
		return nil, err
	}
	for i := range plan {
		r := &plan[i]
		if r.Source != "personal_rules" || r.Index <= len(cfg.PersonalRules) {
			continue
		}
		index := r.Index - len(cfg.PersonalRules) - 1
		r.Source, r.Index = "subscription_cache", index+1
		if index < len(cache.Result.RuleOrigins) {
			origin := cache.Result.RuleOrigins[index]
			r.Source, r.Index = "subscriptions."+origin.Source, origin.Index
		}
	}
	return plan, nil
}
