//go:build darwin

package engine

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"netlaunch/internal/auth"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/serviceprotocol"
)

// RequestDarwinCompanyChange is called only by the private administrator
// entry point. A successful request is queued, not a confirmation of applied
// routing. The owning coordinator confirms native effects separately.
func RequestDarwinCompanyChange(run, requestID string, generation uint64, enabled bool) error {
	if !serviceprotocol.ValidID(requestID) || generation == 0 {
		return errors.New("invalid macOS company request identity")
	}
	return update(run, func(s *State) error {
		if err := checkDarwinCompanyOwner(run, *s); err != nil {
			return err
		}
		runner, err := platform.Process(s.Runner.PID)
		if err != nil || runner != s.Runner {
			return errors.New("administrator coordinator no longer matches the active run")
		}
		if err := guard(run, s); err != nil {
			return err
		}
		return queueDarwinCompanyChange(s, requestID, generation, enabled)
	})
}

func checkDarwinCompanyOwner(run string, s State) error {
	if err := guard(run, &s); err != nil {
		return err
	}
	return requireActiveDarwinOwner(run, s)
}

func queueDarwinCompanyChange(s *State, requestID string, generation uint64, enabled bool) error {
	if s.DarwinCompany == nil || s.Manifest.Mode == "" || !s.TakeoverActive {
		return errors.New("run was not prepared for company channel changes")
	}
	intent := currentIntent(*s)
	if s.DarwinCompany.RequestID == requestID {
		if s.DarwinCompany.RequestGeneration != generation || s.DarwinCompany.Enabled != enabled {
			return errors.New("company request identity was already used with different contents")
		}
		return nil
	}
	if s.DarwinAutoFallbackPending || s.DarwinCompany.Pending || s.DarwinPersonal != nil && s.DarwinPersonal.Pending || s.ChannelGeneration != generation || s.AppliedGeneration != generation ||
		s.AppliedChannels == nil || *s.AppliedChannels != intent {
		return errors.New("company request generation is stale or another change is pending")
	}
	changed := intent.Company != enabled
	if changed {
		if s.ChannelGeneration == ^uint64(0) {
			return errors.New("company request generation exhausted")
		}
		intent.Company = enabled
		if err := s.Manifest.Config.ValidateForIntent(intent); err != nil {
			return err
		}
	}
	s.DarwinCompany = &darwinCompanyControl{RequestID: requestID, RequestGeneration: generation, Enabled: enabled, Pending: changed}
	return nil
}

// Only the coordinator moves a queued command into DesiredChannels. An admin
// request arriving during a probe or reconnect cannot change that native
// operation's intent underneath it.
func beginDarwinCompanyChange(s *State) error {
	record := s.DarwinCompany
	intent := currentIntent(*s)
	if record == nil || !record.Pending || !s.TakeoverActive || s.AppliedChannels == nil || *s.AppliedChannels != intent ||
		s.ChannelGeneration != record.RequestGeneration || s.ChannelGeneration != s.AppliedGeneration ||
		s.ChannelGeneration == ^uint64(0) || intent.Company == record.Enabled {
		return errors.New("invalid queued company change")
	}
	intent.Company = record.Enabled
	s.DesiredChannels = &intent
	s.ChannelGeneration++
	if !intent.Company {
		retireDarwinVPNAttempt(s)
		revokeDarwinCompanyState(s)
	}
	return nil
}

type darwinCompanyTransition struct {
	runDigest  string
	runner     platform.Identity
	generation uint64
	want       policy.ChannelIntent
}

func pendingDarwinCompanyChange(s State) (darwinCompanyTransition, error) {
	if s.DarwinCompany == nil || !s.DarwinCompany.Pending || s.DesiredChannels == nil || s.AppliedChannels == nil ||
		!s.TakeoverActive || s.ChannelGeneration <= s.AppliedGeneration || s.ChannelGeneration-s.AppliedGeneration != 1 ||
		s.AppliedGeneration != s.DarwinCompany.RequestGeneration {
		return darwinCompanyTransition{}, errors.New("invalid pending company change")
	}
	previous := *s.AppliedChannels
	previous.Company = !previous.Company
	if previous != *s.DesiredChannels || s.DesiredChannels.Company != s.DarwinCompany.Enabled {
		return darwinCompanyTransition{}, errors.New("pending change exceeds company intent")
	}
	return darwinCompanyTransition{s.RunSpecDigest, s.Runner, s.ChannelGeneration, *s.DesiredChannels}, nil
}

func (change darwinCompanyTransition) confirm(s *State) error {
	current, err := pendingDarwinCompanyChange(*s)
	if err != nil || current != change {
		return errors.New("company transition no longer belongs to the active run generation")
	}
	intent := change.want
	s.AppliedChannels = &intent
	s.AppliedGeneration = change.generation
	record := *s.DarwinCompany
	record.Pending = false
	s.DarwinCompany = &record
	if s.Phase == "authentication_required" || s.Phase == "company_unavailable" {
		s.Phase, s.Error = "managed", ""
	}
	return nil
}

func (change darwinCompanyTransition) apply(closeGate, stopVPN, publish func() error) error {
	if change.want.Company {
		if err := closeGate(); err != nil {
			return err
		}
	} else if err := stopVPN(); err != nil {
		return err
	}
	return publish()
}

func applyPendingDarwinCompanyChange(run string, company *companyRuntime) (policy.ChannelIntent, error) {
	if company == nil || company.run != run {
		return policy.ChannelIntent{}, errors.New("company ingress disappeared during transition")
	}
	var change darwinCompanyTransition
	var canceled bool
	if err := update(run, func(state *State) error {
		if err := checkDarwinCompanyOwner(run, *state); err != nil {
			return err
		}
		if record := state.DarwinCompany; record != nil && record.DesktopBound && !darwinCompanyPermit(run, record.RequestID) {
			state.DarwinCompany = &darwinCompanyControl{}
			canceled = true
			return nil
		}
		if err := beginDarwinCompanyChange(state); err != nil {
			return err
		}
		var err error
		change, err = pendingDarwinCompanyChange(*state)
		return err
	}); err != nil {
		return policy.ChannelIntent{}, err
	}
	if canceled {
		return policy.ChannelIntent{}, errDarwinCompanyRequestCanceled
	}
	check := func(state *State) error {
		if err := checkDarwinCompanyOwner(run, *state); err != nil {
			return err
		}
		current, err := pendingDarwinCompanyChange(*state)
		if err != nil || current != change {
			return errors.New("company transition changed before native application")
		}
		return nil
	}
	err := change.apply(func() error {
		return update(run, func(state *State) error {
			if err := check(state); err != nil {
				return err
			}
			return closeDarwinCompanyGate(run, *state)
		})
	}, func() error {
		return stopDarwinVPN(run, company, check)
	}, func() error {
		return update(run, func(state *State) error {
			if err := check(state); err != nil {
				return err
			}
			return change.confirm(state)
		})
	})
	return change.want, err
}

func readDarwinCompanyRefresh(run string, state State) (auth.Session, bool, error) {
	raw, err := securefile.Read(filepath.Join(run, "auth-refresh.json"), 768<<10, true)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || state.DarwinCompany != nil {
			return auth.Session{}, false, nil
		}
		return auth.Session{}, false, err
	}
	defer clear(raw)
	return decodeDarwinCompanyRefresh(raw, state, time.Now())
}

func decodeDarwinCompanyRefresh(raw []byte, state State, now time.Time) (auth.Session, bool, error) {
	if state.DarwinCompany != nil {
		var envelope struct {
			Generation uint64          `json:"generation"`
			VPN        policy.VPN      `json:"vpn"`
			Session    json.RawMessage `json:"session"`
		}
		if !currentIntent(state).Company || state.DarwinCompany.Pending || state.ChannelGeneration != state.AppliedGeneration ||
			json.Unmarshal(raw, &envelope) != nil || envelope.Generation != state.AppliedGeneration || envelope.VPN != state.Manifest.Config.VPN {
			return auth.Session{}, false, nil
		}
		defer clear(envelope.Session)
		raw = envelope.Session
	}
	session, err := auth.DecodeRuntime(state.Manifest.Config.VPN, raw)
	if err != nil || requireVPNAuthentication(session, state.Manifest.Config.VPN, now) != nil {
		if state.DarwinCompany != nil {
			return auth.Session{}, false, nil
		}
		return auth.Session{}, false, errors.New("invalid refreshed authentication")
	}
	return session, true, nil
}

func saveDarwinCompanyRefresh(run string, observed State, session auth.Session) (bool, error) {
	adopted := false
	err := update(run, func(s *State) error {
		if err := checkDarwinCompanyOwner(run, *s); err != nil {
			return err
		}
		if s.RunSpecDigest != observed.RunSpecDigest || s.Runner != observed.Runner ||
			s.ChannelGeneration != observed.ChannelGeneration || !currentIntent(*s).Company ||
			(s.DarwinCompany != nil && s.DarwinCompany.Pending) {
			return nil
		}
		if err := requireVPNAuthentication(session, s.Manifest.Config.VPN, time.Now()); err != nil {
			return nil
		}
		if err := writeRunFile(run, "auth.json", session); err != nil {
			return err
		}
		adopted = true
		return nil
	})
	return adopted, err
}
