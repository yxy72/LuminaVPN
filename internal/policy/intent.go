package policy

// ChannelIntent controls the two optional channels. The base TUN, local DNS and
// IPv6 protection remain active even when both channels are disabled.
type ChannelIntent struct {
	Company     bool   `json:"company"`
	Personal    bool   `json:"personal"`
	Environment string `json:"environment,omitempty"`
}

// DefaultIntent preserves the existing CLI behavior when no explicit intent
// was supplied by the desktop client.
func DefaultIntent() ChannelIntent { return ChannelIntent{Company: true, Personal: true} }

type Override struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Target string `json:"target"`
}

func (c Config) environmentRules(intent ChannelIntent) ([]Rule, error) {
	var selected []Override
	switch intent.Environment {
	case "":
		return nil, nil
	case "office":
		selected = c.OfficeOverrides
	case "home":
		selected = c.HomeOverrides
	default:
		return nil, fieldError("environment", "expected office or home")
	}
	return overrideRules(selected)
}
func overrideRules(overrides []Override) ([]Rule, error) {
	if len(overrides) > 128 {
		return nil, fieldError("overrides", "at most 128 overrides")
	}
	rules := make([]Rule, 0, len(overrides))
	for _, o := range overrides {
		typ := map[string]string{"domain": "DOMAIN", "domain_suffix": "DOMAIN-SUFFIX", "cidr": "IP-CIDR"}[o.Type]
		if typ == "" || (o.Target != "personal" && o.Target != "direct") {
			return nil, fieldError("overrides", "invalid override type or target")
		}
		rules = append(rules, Rule{Type: typ, Value: o.Value, Target: o.Target})
	}
	return rules, ValidateRules(rules)
}
