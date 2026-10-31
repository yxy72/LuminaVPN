package app

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
)

func (c CLI) configMaintenance(args []string) error {
	command := args[1]
	profile, err := DefaultProfile()
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	o := options{profile: profile, runtime: filepath.Join(filepath.Dir(executable), "runtime")}
	var file, revision string
	var restart bool
	fs := flag.NewFlagSet("config "+command, flag.ContinueOnError)
	fs.SetOutput(c.Err)
	fs.StringVar(&o.profile, "profile", profile, "private local profile directory")
	fs.StringVar(&file, "file", "", "candidate policy JSON")
	fs.StringVar(&revision, "revision", "", "rollback: full saved revision identifier")
	fs.BoolVar(&restart, "restart", false, "apply/rollback: recover the previous run and start the candidate")
	fs.StringVar(&o.runtime, "runtime", o.runtime, "restart: bundled runtime directory")
	fs.DurationVar(&o.sessionTimeout, "session-timeout", 0, "restart: Windows home session limit")
	fs.DurationVar(&o.validationTimeout, "validation-timeout", 0, "restart: Windows validation deadline")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected configuration arguments")
	}
	mutating := command == "apply" || command == "rollback"
	if !mutating && (restart || revision != "" || o.sessionTimeout != 0 || o.validationTimeout != 0) {
		return errors.New("restart options require config apply or rollback")
	}
	if !restart && (o.sessionTimeout != 0 || o.validationTimeout != 0) {
		return errors.New("session limits require --restart")
	}
	if (command == "diff" || command == "apply") && (file == "" || revision != "") {
		return errors.New("config diff/apply requires --file and does not accept --revision")
	}
	if (command == "rollback" || command == "history") && file != "" {
		return errors.New("config rollback/history does not accept --file")
	}
	o.profile, err = filepath.Abs(o.profile)
	if err != nil {
		return err
	}
	o.runtime, err = filepath.Abs(o.runtime)
	if err != nil {
		return err
	}
	if restart {
		if !platform.Supported() {
			return errors.New("configuration restart requires a native lifecycle build")
		}
		if err := validateLaunchOptions(&o, "up"); err != nil {
			return err
		}
	}
	if command == "history" {
		return c.configHistory(o.profile)
	}
	if mutating {
		unlock, err := securefile.Lock(filepath.Join(o.profile, "launch.lock"), time.Second)
		if err != nil {
			return err
		}
		defer unlock()
	}
	var candidate policy.Config
	if command == "rollback" {
		candidate, err = rollbackPolicy(o.profile, revision)
	} else {
		candidate, err = readCandidate(file)
	}
	if err != nil {
		return configChangeError(command, err)
	}
	if command == "diff" {
		return c.configDiff(o.profile, candidate)
	}
	life := configLifecycle{
		running: func() (bool, error) { return profileRunning(o) },
		stop: func() error {
			active, err := profileRunning(o)
			if err != nil {
				return err
			}
			if !active {
				return nil
			}
			return c.down(o)
		},
		start: func(cfg policy.Config, nodes []policy.Node) error { return c.upLocked(o, cfg, nodes) },
	}
	result, err := changeConfig(o.profile, candidate, restart, command == "rollback", life)
	if err != nil {
		return configChangeError(command, err)
	}
	return c.json(result)
}

func readCandidate(path string) (policy.Config, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return policy.Config{}, err
	}
	raw, err := securefile.Read(path, 1<<20, false)
	if err != nil {
		return policy.Config{}, errors.New("candidate policy is not a readable bounded regular file")
	}
	return policy.Decode(raw)
}

func profileRunning(o options) (bool, error) {
	if _, err := os.Lstat(filepath.Join(o.profile, "current.json")); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	run, err := currentRun(o)
	if err != nil {
		return false, err
	}
	status, err := statusFor(run)
	if err != nil {
		return false, err
	}
	return status.Phase != "stopped", nil
}

type configFieldChange struct {
	Field  string `json:"field"`
	Before any    `json:"before"`
	After  any    `json:"after"`
}

func diffPolicy(before, after policy.Config) []configFieldChange {
	var left, right map[string]any
	b, _ := json.Marshal(before)
	_ = json.Unmarshal(b, &left)
	b, _ = json.Marshal(after)
	_ = json.Unmarshal(b, &right)
	out := []configFieldChange{}
	var walk func(string, map[string]any, map[string]any)
	walk = func(prefix string, a, b map[string]any) {
		keys := map[string]bool{}
		for key := range a {
			keys[key] = true
		}
		for key := range b {
			keys[key] = true
		}
		ordered := make([]string, 0, len(keys))
		for key := range keys {
			ordered = append(ordered, key)
		}
		sort.Strings(ordered)
		for _, key := range ordered {
			path := prefix + key
			if reflect.DeepEqual(a[key], b[key]) {
				continue
			}
			am, aok := a[key].(map[string]any)
			bm, bok := b[key].(map[string]any)
			if aok && bok {
				walk(path+".", am, bm)
			} else {
				out = append(out, configFieldChange{Field: path, Before: a[key], After: b[key]})
			}
		}
	}
	walk("", left, right)
	return out
}
func (c CLI) configDiff(profile string, candidate policy.Config) error {
	before, err := readPolicy(profile)
	if err != nil {
		return err
	}
	oldPlan, err := effectiveRulePlan(profile, before)
	if err != nil {
		return err
	}
	newPlan, err := effectiveRulePlan(profile, candidate)
	if err != nil {
		return err
	}
	// The arrays preserve precedence. Moving an otherwise identical rule is a
	// behavior change, so never reduce this comparison to unordered sets.
	return c.json(map[string]any{"from": policyRevision(before), "to": policyRevision(candidate), "changed_fields": diffPolicy(before, candidate), "rule_plan_changed": !reflect.DeepEqual(oldPlan, newPlan), "rules_before": len(oldPlan), "rules_after": len(newPlan), "static_only": true})
}
