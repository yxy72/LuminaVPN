package engine

import (
	"netlaunch/internal/auth"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"testing"
	"time"
)

func TestExplicitRunModeBoundaries(t *testing.T) {
	valid := []Manifest{{Mode: Validation, ValidationTimeout: 45 * time.Minute}}
	if !platform.WindowsClientValidationOnly {
		valid = append(valid, Manifest{Mode: Daily}, Manifest{ValidationTimeout: 8 * time.Hour})
	} else if (Manifest{Mode: Daily}).ValidateMode() == nil {
		t.Fatal("validation-only binary accepted daily mode")
	}
	for _, m := range valid {
		if e := m.ValidateMode(); e != nil {
			t.Fatal(e)
		}
	}
	for _, m := range []Manifest{{Mode: Daily, ValidationTimeout: time.Second}, {Mode: Validation}, {Mode: Validation, ValidationTimeout: 45*time.Minute + time.Nanosecond}, {Mode: Legacy}, {Mode: "other"}} {
		if m.ValidateMode() == nil {
			t.Fatal("unsafe mode accepted", m.Mode)
		}
	}
	if (Manifest{}).EffectiveMode() == Daily {
		t.Fatal("old manifest silently became daily")
	}
}

func TestValidationBuildRejectsOmittedModesAtStart(t *testing.T) {
	for _, m := range []Manifest{{}, {ValidationTimeout: 12 * time.Hour}, {Mode: Legacy}, {Mode: Daily}} {
		if platform.WindowsClientValidationOnly && m.ValidateMode() == nil {
			t.Fatal("validation-only native start accepted a non-validation specification", m.Mode, m.ValidationTimeout)
		}
	}
	for _, m := range []Manifest{{}, {ValidationTimeout: 12 * time.Hour}} {
		if err := m.validateRecoveryMode(); err != nil {
			t.Fatal("legacy recovery specification became unreadable", err)
		}
	}
	if err := (Manifest{ValidationTimeout: 12*time.Hour + time.Nanosecond}).validateRecoveryMode(); err == nil {
		t.Fatal("recovery mode bypassed structural validation")
	}
}
func TestModeAndInitialChannelsAreImmutableRunSpec(t *testing.T) {
	intent := policy.ChannelIntent{}
	m := Manifest{Mode: Daily, Channels: &intent}
	before := runSpecDigest(immutableRunSpec(m))
	m.Mode = Validation
	if before == runSpecDigest(immutableRunSpec(m)) {
		t.Fatal("mode omitted from run spec")
	}
	m.Mode = Daily
	intent.Company = true
	if before == runSpecDigest(immutableRunSpec(m)) {
		t.Fatal("channels omitted from run spec")
	}
}
func TestSessionAbsoluteBoundaryNeverRenews(t *testing.T) {
	created := time.Unix(1700000000, 0)
	s := auth.Session{Created: created}
	if !s.ValidAt(created.Add(auth.MaxAge - time.Nanosecond)) {
		t.Fatal("fresh session rejected")
	}
	for _, now := range []time.Time{created.Add(-time.Nanosecond), created.Add(auth.MaxAge), created.Add(auth.MaxAge + time.Second)} {
		if s.ValidAt(now) {
			t.Fatal("expired/future session accepted")
		}
	}
	if s.Created != created {
		t.Fatal("read renewed session")
	}
}
