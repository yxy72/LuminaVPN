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
	if intent.Personal {
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

func darwinCoreConfig(m Manifest, nodes []policy.Node, secret string, company *companyRuntime, verification *personalVerification) (map[string]any, error) {
	intent := m.InitialChannels()
	if (company != nil) != intent.Company || (verification != nil) != intent.Personal {
		return nil, errors.New("macOS channel resources do not match the run intent")
	}
	config, err := policy.CompileWithIntent(m.Config, nodes, m.Binding, secret, intent)
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
	return config, nil
}

func setDarwinPersonalDirect(ctx context.Context, run string) error {
	return update(run, func(s *State) error {
		if err := guard(run, s); err != nil {
			return err
		}
		if s.Manifest.Mode == "" || currentIntent(*s).Personal {
			return errors.New("macOS personal direct requires an explicitly disabled personal channel")
		}
		work, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if err := selectPersonalContext(work, run, "PHYSICAL"); err != nil {
			return err
		}
		s.Personal = "PHYSICAL"
		return nil
	})
}

func applyDarwinTakeover(run string, intent policy.ChannelIntent) error {
	return update(run, func(s *State) error {
		if err := guard(run, s); err != nil {
			return err
		}
		if currentIntent(*s) != intent || s.Manifest.InitialChannels() != intent {
			return errors.New("macOS startup intent changed during takeover")
		}
		if !intent.Personal && s.Personal != "PHYSICAL" {
			return errors.New("macOS personal direct has not been confirmed")
		}
		s.AppliedChannels = &intent
		s.AppliedGeneration = s.ChannelGeneration
		s.TakeoverActive = true
		return nil
	})
}
