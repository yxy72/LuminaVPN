//go:build darwin

package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"netlaunch/internal/auth"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/selector"
)

// Verify only resources this run could own. Evidence of a released VPN still
// requires cleanup even if its recorded startup intent disabled the channel.
func hasDarwinCandidateInterface(s State, present map[string]bool) bool {
	if present[s.Manifest.Binding.TUN] {
		return true
	}
	if !present[s.Manifest.Binding.VPN] {
		return false
	}
	if s.Manifest.InitialChannels().Company || s.VPN.PID != 0 || s.VPN.Interface != "" {
		return true
	}
	for _, child := range s.Children {
		if child.Role == "vpn" {
			return true
		}
	}
	return false
}

func darwinChannelInputs(run string, m Manifest) ([]policy.Node, auth.Session, error) {
	var nodes []policy.Node
	var session auth.Session
	intent := m.InitialChannels()
	if intent.Company {
		raw, err := securefile.Read(filepath.Join(run, "auth.json"), 768<<10, true)
		if err != nil {
			return nil, session, errVPNAuthenticationRequired
		}
		defer clear(raw)
		session, err = auth.DecodeRuntime(m.Config.VPN, raw)
		if err != nil {
			return nil, auth.Session{}, errVPNAuthenticationRequired
		}
	}
	if intent.Personal {
		if err := readJSON(filepath.Join(run, "nodes.json"), &nodes); err != nil {
			return nil, auth.Session{}, err
		}
		var err error
		nodes, err = policy.SanitizeNodes(nodes)
		if err != nil {
			return nil, auth.Session{}, err
		}
	}
	return nodes, session, nil
}

func frozenDarwinPersonalPool(run string, m Manifest, nodes []policy.Node) []policy.Node {
	intent := m.InitialChannels()
	if m.Mode == "" || intent.Personal {
		return nodes
	}
	if err := readJSON(filepath.Join(run, "nodes.json"), &nodes); err != nil {
		return nil
	}
	nodes, err := policy.SanitizeNodes(nodes)
	if err != nil || len(nodes) == 0 {
		return nil
	}
	intent.Personal = true
	if m.Config.ValidateForIntent(intent) != nil || policy.ValidateEndpointsForIntent(m.Config, nodes, intent) != nil {
		return nil
	}
	return nodes
}

func freezeDarwinChannelInputs(run string, m Manifest) ([]policy.Node, error) {
	nodes, session, err := darwinChannelInputs(run, m)
	if err != nil {
		return nil, err
	}
	intent := m.InitialChannels()
	if intent.Company {
		if err := securefile.Write(filepath.Join(private(run), "auth.json"), session); err != nil {
			return nil, err
		}
		_ = os.Remove(filepath.Join(run, "auth.json"))
	}
	nodes = frozenDarwinPersonalPool(run, m, nodes)
	if len(nodes) != 0 {
		if err := securefile.Write(filepath.Join(private(run), "nodes.json"), nodes); err != nil {
			return nil, err
		}
	}
	_ = os.Remove(filepath.Join(run, "nodes.json"))
	return nodes, nil
}

func closeDarwinVerification(run string, verification *personalVerification) error {
	if verification == nil {
		return nil
	}
	return verification.close(run)
}

func darwinCanRetainCompany(m Manifest, nodes []policy.Node) bool {
	intent := m.InitialChannels()
	if intent.Company {
		return true
	}
	if m.Mode == "" {
		return false
	}
	// A managed run can reserve the company ingress ahead of time if its
	// frozen configuration can safely support the complete company policy.
	// An incomplete disabled channel keeps the static reject policy.
	intent.Company = true
	return m.Config.ValidateForIntent(intent) == nil && policy.ValidateEndpointsForIntent(m.Config, nodes, intent) == nil
}

func darwinCoreConfig(m Manifest, nodes []policy.Node, secret string, company *companyRuntime, verification *personalVerification, fallback bool) (map[string]any, error) {
	intent := m.InitialChannels()
	if (intent.Company && company == nil) || (verification != nil) != (intent.Personal && !fallback) ||
		fallback && (m.Mode == "" || !intent.Personal) {
		return nil, errors.New("macOS channel resources do not match the run intent")
	}
	// Keep the same company rules and resolver in both live states. CORP
	// starts at REJECT and the authenticated ingress needs an active lease.
	intent.Company = company != nil
	compile := policy.CompileWithIntent
	if fallback {
		compile = policy.CompilePersonalFallback
	}
	config, err := compile(m.Config, nodes, m.Binding, secret, intent)
	if err != nil {
		return nil, err
	}
	if company != nil {
		if err := company.configure(config); err != nil {
			return nil, err
		}
	}
	if verification != nil {
		verification.ingress.configure(config, m.Config, candidateNames(nodes))
	}
	if m.Mode != "" {
		if err := addDesktopPhysicalGate(config); err != nil {
			return nil, err
		}
	}
	return config, nil
}

func darwinStartupIntentMatches(s State, intent policy.ChannelIntent) bool {
	return s.Manifest.Mode != "" && !s.TakeoverActive && s.ChannelGeneration != 0 &&
		s.AppliedGeneration == 0 && s.AppliedChannels == nil && s.DesiredChannels != nil &&
		*s.DesiredChannels == intent && s.Manifest.InitialChannels() == intent
}

func markDarwinBaseApplied(s *State, intent policy.ChannelIntent, companyControl, personalControl bool, now time.Time) error {
	if !darwinStartupIntentMatches(*s, intent) {
		return errors.New("macOS startup intent changed during takeover")
	}
	personal := "PHYSICAL"
	if intent.Personal {
		personal = selector.Reject
	}
	if s.Personal != personal || systemBaseReadyAt(*s, now).IsZero() {
		return errors.New("macOS managed base routing has not been verified")
	}
	s.AppliedChannels = &intent
	s.AppliedGeneration = s.ChannelGeneration
	s.TakeoverActive = true
	if companyControl {
		s.DarwinCompany = &darwinCompanyControl{}
	}
	if personalControl {
		s.DarwinPersonal = &darwinPersonalControl{}
	}
	if intent.Personal {
		s.Channels["personal"] = ChannelHealth{
			ChannelStatus: ChannelStatus{State: "unknown", Reason: "probe_incomplete", NextAction: "wait_for_selection"},
			Network:       s.Manifest.Network, Node: selector.Reject,
		}
	}
	desktopPhase(s, now)
	return nil
}

func applyDarwinTakeover(ctx context.Context, run string, intent policy.ChannelIntent, companyControl, personalControl bool) error {
	return update(run, func(s *State) error {
		if err := checkDarwinCompanyOwner(run, *s); err != nil {
			return err
		}
		if !darwinStartupIntentMatches(*s, intent) {
			return errors.New("macOS startup intent changed during takeover")
		}
		if err := verifyDarwinPersonalResolverOwnership(*s); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		personal := "PHYSICAL"
		if intent.Personal {
			personal = selector.Reject
		}
		if err := selectPersonalContext(ctx, run, personal); err != nil {
			return err
		}
		if !intent.Company {
			if err := selectCoreGroupContext(ctx, run, "CORP", selector.Reject); err != nil {
				return err
			}
		}
		if err := guard(run, s); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return markDarwinBaseApplied(s, intent, companyControl, personalControl, time.Now())
	})
}
