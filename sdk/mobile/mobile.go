// Package mobile exposes offline LuminaVPN policy operations to app bindings.
// Input and output use owned bytes so callers can use the same API from Go or
// a mobile binding without importing private packages or desktop services.
package mobile

import (
	"encoding/json"
	"errors"

	"netlaunch/internal/policy"
	"netlaunch/internal/subscription"
)

// APIVersion reports the version of this API and its returned JSON shapes.
func APIVersion() int { return 1 }

// ValidateStoredPolicyJSON validates a versioned policy for storage. A profile
// can be saved before its connection settings are complete.
func ValidateStoredPolicyJSON(data []byte) error {
	_, err := policy.DecodeForStorage(data)
	return err
}

// RulePlan contains immutable rules in execution order. A plan describes static
// routing intent. Connection state, DNS, and transport health are evaluated by
// the platform using the plan.
type RulePlan struct {
	rules []policy.PlannedRule
}

// BuildRulePlan validates a policy for the requested channels and computes its
// static rules. Use an empty environment for the shared configuration, or
// "office" or "home" to apply that override.
func BuildRulePlan(data []byte, company, personal bool, environment string) (*RulePlan, error) {
	intent := policy.ChannelIntent{Company: company, Personal: personal, Environment: environment}
	cfg, err := policy.DecodeForIntent(data, intent)
	if err != nil {
		return nil, err
	}
	rules, err := policy.RulePlanForIntent(cfg, intent)
	if err != nil {
		return nil, err
	}
	return &RulePlan{rules: rules}, nil
}

// RulesJSON returns the ordered rules as a JSON array. Each entry has a type,
// value, target, source, index, and optional guard flag.
func (p *RulePlan) RulesJSON() ([]byte, error) {
	if p == nil || len(p.rules) == 0 {
		return nil, errors.New("rule plan has not been built")
	}
	return json.Marshal(p.rules)
}

// ExplainJSON returns the winning and shadowed rules for an exact hostname or
// literal IPv4 address. It never performs DNS resolution.
func (p *RulePlan) ExplainJSON(target string) ([]byte, error) {
	if p == nil || len(p.rules) == 0 {
		return nil, errors.New("rule plan has not been built")
	}
	explanation, err := policy.Explain(p.rules, target)
	if err != nil {
		return nil, err
	}
	return json.Marshal(explanation)
}

// ParseRuleSubscriptionJSON parses caller-provided YAML or JSON. Formats are
// "classical", "domain", and "ipcidr"; the default is "classical". The default
// target is "personal", and "direct" and "reject" are also supported.
// The JSON result contains rules, one-based source_indexes, and optional issues.
// Issues identify skipped entries without including their raw text.
func ParseRuleSubscriptionJSON(data []byte, format, target string, strict bool) ([]byte, error) {
	switch format {
	case "", "classical", "domain", "ipcidr":
	default:
		return nil, errors.New("unsupported rule source format")
	}
	switch target {
	case "", "personal", "direct", "reject":
	default:
		return nil, errors.New("invalid rule source target")
	}
	report, err := subscription.ParseRulesDetailed(data, subscription.Source{
		Format: format, Target: target, StrictRules: strict,
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(ruleImport{
		Rules:         report.Rules,
		SourceIndexes: report.Indexes,
		Issues:        report.Issues,
	})
}

type ruleImport struct {
	Rules         []policy.Rule            `json:"rules"`
	SourceIndexes []int                    `json:"source_indexes"`
	Issues        []subscription.RuleIssue `json:"issues,omitempty"`
}
