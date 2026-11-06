package engine

import (
	"errors"
	"time"

	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
)

type RunMode string

const (
	Legacy     RunMode = "legacy"
	Daily      RunMode = "daily"
	Validation RunMode = "validation"
)

// EffectiveMode keeps pre-desktop manifests readable. New callers must write
// an explicit mode; legacy manifests with a timeout remain validation runs.
func (m Manifest) EffectiveMode() RunMode {
	if m.Mode != "" {
		return m.Mode
	}
	return Legacy
}

func (m Manifest) InitialChannels() policy.ChannelIntent {
	if m.Channels == nil {
		return policy.DefaultIntent()
	}
	return *m.Channels
}

func (m Manifest) ValidateMode() error {
	if platform.WindowsClientValidationOnly && m.Mode != Validation {
		return errors.New("explicit validation mode required by validation-only client build")
	}
	return m.validateRecoveryMode()
}

// validateRecoveryMode checks immutable data without authorizing a new native
// start. Recovery may read legacy specifications written before explicit modes.
func (m Manifest) validateRecoveryMode() error {
	if m.Service != nil {
		if err := m.Service.Validate(m.Mode, m.Created); err != nil {
			return err
		}
		if !serviceDigest.MatchString(m.Service.NodesSHA256) || !serviceDigest.MatchString(m.Service.RuntimeSHA256) || !serviceDigest.MatchString(m.Service.LifecycleSHA256) {
			return errors.New("service input digests missing")
		}
	}
	switch m.EffectiveMode() {
	case Daily:
		if m.ValidationTimeout != 0 {
			return errors.New("daily mode cannot have a validation deadline")
		}
	case Validation:
		if m.ValidationTimeout < time.Second || m.ValidationTimeout > 45*time.Minute {
			return errors.New("validation mode requires a hard deadline no longer than 45 minutes")
		}
	case Legacy:
		if m.Mode != "" {
			return errors.New("legacy mode cannot be explicitly requested")
		}
		if m.ValidationTimeout != 0 && (m.ValidationTimeout < time.Second || m.ValidationTimeout > 12*time.Hour) {
			return errors.New("invalid legacy validation timeout")
		}
	default:
		return errors.New("unsupported run mode")
	}
	return nil
}
