//go:build darwin

package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/selector"
)

var errDarwinPersonalPreflight = errors.New("macOS frozen personal configuration could not be prepared")

func queueDarwinPersonalChange(s *State, r DarwinDesktopPersonalRequest) error {
	if s.DarwinPersonal == nil || s.Manifest.Mode == "" || !s.TakeoverActive {
		return errors.New("run has no frozen personal candidate pool")
	}
	if s.DarwinPersonal.RequestID == r.ID {
		if !r.matches(s.DarwinPersonal) {
			return errors.New("personal request identity was already used with different contents")
		}
		return nil
	}
	intent := currentIntent(*s)
	if s.DarwinAutoFallbackPending || s.DarwinPersonal.Pending || s.DarwinCompany != nil && s.DarwinCompany.Pending ||
		s.ChannelGeneration != r.Generation || s.AppliedGeneration != r.Generation ||
		s.AppliedChannels == nil || *s.AppliedChannels != intent || intent.Company != r.Company || intent.Personal == r.Personal {
		return errors.New("personal request generation or unchanged Company intent is stale")
	}
	s.DarwinPersonal = &darwinPersonalControl{
		RequestID: r.ID, RequestGeneration: r.Generation, Company: r.Company, Enabled: r.Personal, Pending: true,
	}
	return nil
}

type darwinPersonalChange struct {
	request darwinPersonalControl
	digest  string
	runner  platform.Identity
	network platform.Network
	from    policy.ChannelIntent
	to      policy.ChannelIntent
}

func pendingDarwinPersonalChange(s State) (darwinPersonalChange, error) {
	record, intent := s.DarwinPersonal, currentIntent(s)
	if record == nil || !record.Pending || record.Failed || !s.TakeoverActive ||
		s.DarwinCompany != nil && s.DarwinCompany.Pending ||
		s.ChannelGeneration != record.RequestGeneration || s.ChannelGeneration != s.AppliedGeneration ||
		s.ChannelGeneration == 0 || s.ChannelGeneration == ^uint64(0) ||
		s.AppliedChannels == nil || *s.AppliedChannels != intent || intent.Company != record.Company || intent.Personal == record.Enabled {
		return darwinPersonalChange{}, errors.New("invalid pending macOS personal change")
	}
	wanted := intent
	wanted.Personal = record.Enabled
	return darwinPersonalChange{*record, s.RunSpecDigest, s.Runner, s.Manifest.Network, intent, wanted}, nil
}

func (change darwinPersonalChange) check(run string, s State) error {
	if err := checkDarwinCompanyOwner(run, s); err != nil {
		return err
	}
	current, err := pendingDarwinPersonalChange(s)
	if err != nil || current != change {
		return errors.New("personal change no longer belongs to this run generation")
	}
	if !darwinPersonalPermit(run, change.request.RequestID) {
		return errDarwinPersonalRequestCanceled
	}
	return nil
}

func (change darwinPersonalChange) publish(s *State, check func(State) error, selectGroup func(group, target string) error) error {
	if err := check(*s); err != nil {
		return err
	}
	if err := openDesktopConfig(func(group, target string) error {
		if err := check(*s); err != nil {
			return err
		}
		return selectGroup(group, target)
	}, !change.to.Personal); err != nil {
		return err
	}
	if err := check(*s); err != nil {
		return err
	}
	fromRequest := change.request
	fromRequest.Pending = false
	s.DarwinPersonal = &fromRequest
	s.DesiredChannels, s.AppliedChannels = &change.to, &change.to
	s.ChannelGeneration++
	s.AppliedGeneration = s.ChannelGeneration
	s.Personal, s.PersonalFallback = selector.Reject, false
	s.DarwinAutoFallbackUntil = nil
	if !change.to.Personal {
		s.Personal = "PHYSICAL"
	}
	return nil
}

func (change darwinPersonalChange) decline(run string, failure error) error {
	if err := update(run, func(s *State) error {
		if err := checkDarwinCompanyOwner(run, *s); err != nil {
			return err
		}
		current, err := pendingDarwinPersonalChange(*s)
		if err != nil || current != change {
			return errors.New("personal change changed before preflight completed")
		}
		record := change.request
		record.Pending, record.Failed = false, true
		s.DarwinPersonal = &record
		return nil
	}); err != nil {
		return err
	}
	return failure
}

func stageDarwinPersonalConfig(ctx context.Context, run string, m Manifest, nodes []policy.Node, company *companyRuntime, secret string, keepCandidateAdapters bool) (map[string]any, *personalVerification, error) {
	var verification *personalVerification
	if m.InitialChannels().Personal {
		if len(nodes) == 0 || policy.ValidateEndpointsForIntent(m.Config, nodes, m.InitialChannels()) != nil {
			return nil, nil, errDarwinPersonalPreflight
		}
		var err error
		verification, err = newPersonalVerification(m)
		if err != nil {
			return nil, nil, err
		}
	} else if !keepCandidateAdapters {
		nodes = nil
	}
	config, err := darwinCoreConfig(m, nodes, secret, company, verification)
	if err != nil {
		return nil, nil, err
	}
	config["tun"].(map[string]any)["enable"] = true
	dir, err := securefile.TempDir(private(run), "personal-config-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "core.json")
	if err := securefile.Write(path, config); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := native(ctx, filepath.Join(private(run), "runtime/bin/mihomo"), "-t", "-d", dir, "-f", path); err != nil {
		return nil, nil, err
	}
	return config, verification, nil
}

func applyPendingDarwinPersonalChange(ctx context.Context, run string, before State, company *companyRuntime, previous *personalVerification, frozenNodes []policy.Node, secret string) (policy.ChannelIntent, *personalVerification, error) {
	change, err := pendingDarwinPersonalChange(before)
	if err != nil {
		return policy.ChannelIntent{}, nil, err
	}
	if !darwinPersonalPermit(run, change.request.RequestID) {
		return policy.ChannelIntent{}, nil, change.decline(run, errDarwinPersonalRequestCanceled)
	}
	manifest := before.Manifest
	manifest.Channels = &change.to
	config, verification, err := stageDarwinPersonalConfig(ctx, run, manifest, frozenNodes, company, secret, false)
	if err != nil {
		return policy.ChannelIntent{}, nil, change.decline(run, errDarwinPersonalPreflight)
	}
	if network, err := platform.Discover(); err != nil || network != change.network {
		return policy.ChannelIntent{}, nil, change.decline(run, errDarwinPersonalPreflight)
	}
	if err := update(run, func(s *State) error {
		if err := change.check(run, *s); err != nil {
			return err
		}
		s.Channels = nil
		s.Personal, s.Phase = selector.Reject, "reconnecting"
		return nil
	}); err != nil {
		if errors.Is(err, errDarwinPersonalRequestCanceled) {
			err = change.decline(run, errDarwinPersonalRequestCanceled)
		}
		return policy.ChannelIntent{}, nil, err
	}
	// Beyond this point failure must enter owned recovery with egress closed.
	if err := closeDarwinVerification(run, previous); err != nil {
		return policy.ChannelIntent{}, nil, errors.Join(err, closeDarwinBasePaths(ctx, run))
	}
	authorize := func(s State) error { return change.check(run, s) }
	if err := prepareDarwinPersonalReload(ctx, run, before, config, authorize); err != nil {
		// Losing a permit after preparation began cannot be treated as cancel-before-start.
		return policy.ChannelIntent{}, nil, errors.Join(errors.New("macOS personal resolver preparation was interrupted"), closeDarwinBasePaths(ctx, run))
	}
	if err := confirmDarwinPersonalChange(ctx, run, before, change, authorize); err != nil {
		return policy.ChannelIntent{}, nil, errors.Join(err, closeDarwinBasePaths(ctx, run))
	}
	return change.to, verification, nil
}

func verifyDarwinPersonalResolverOwnership(before State) error {
	network, err := platform.Discover()
	if err != nil || network != before.Manifest.Network {
		return errors.New("macOS physical network changed during personal resolver transition")
	}
	owned, ok := before.DNS[network.Service]
	if !ok || !slices.Equal(owned.After, []string{"127.0.0.1"}) {
		return errors.New("macOS personal transition lacks a DNS ownership record")
	}
	dns, err := platform.DNS(network.Service)
	if err != nil || !slices.Equal(dns, owned.After) {
		return errors.New("macOS system DNS changed during personal resolver transition")
	}
	return nil
}

func confirmDarwinPersonalChange(ctx context.Context, run string, before State, change darwinPersonalChange, authorize func(State) error) error {
	if err := verifyDarwinPersonalResolverOwnership(before); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := update(run, func(s *State) error {
		return change.publish(s, authorize, func(group, target string) error {
			return selectCoreGroupContext(ctx, run, group, target)
		})
	}); err != nil {
		return errors.New("macOS personal transition could not publish verified egress")
	}
	return nil
}
