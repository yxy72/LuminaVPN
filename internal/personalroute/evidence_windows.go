//go:build windows

// Package personalroute decides whether Windows may use the direct personal
// exit. It does not change a selector, DNS, routes, or company authorization.
package personalroute

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"
)

const DefaultMaxAge = 45 * time.Second

// Generation binds evidence to one run, physical-network epoch and independent
// health sweep. The caller must replace Probe after pool/configuration changes
// (including changing a pool back), and discard workers from older generations.
type Generation struct {
	Run     string
	Network string
	Probe   string
}

type Scope string

const (
	IndependentHealth Scope = "independent_health"
	TargetRequest     Scope = "target_request"
)

type Outcome string

const (
	Unknown       Outcome = "unknown"
	Healthy       Outcome = "healthy"
	PathFailed    Outcome = "path_failed"
	Canceled      Outcome = "canceled"
	ServiceFailed Outcome = "service_failed"
)

// Observation describes an independent node check, not selector.REJECT or a
// request through the currently selected group. PathFailed means an explicit
// path failure; cancellation, missing results, controller errors and HTTP-only
// service failures must remain Unknown/Canceled/ServiceFailed, never PathFailed.
type Observation struct {
	CandidateID string
	PoolID      string
	Generation  Generation
	Scope       Scope
	Outcome     Outcome
	StartedAt   time.Time
	FinishedAt  time.Time
}

type Input struct {
	// Only an explicit resolved user setting may set ManualDisabled. Its zero
	// value does not accidentally authorize direct access before initialization.
	ManualDisabled bool
	Generation     Generation
	// Candidates is the complete enabled pool, not a NextBatch/cooldown subset.
	// IDs must bind node configuration, not merely mutable display names.
	Candidates   []string
	Observations []Observation
	Now          time.Time
	// Zero selects DefaultMaxAge. A positive value may only tighten that bound.
	MaxAge time.Duration
}

type Decision struct {
	DirectAllowed bool
	Reason        string
}

const (
	ReasonManualDisabled    = "manual_disabled"
	ReasonAllFailed         = "all_candidates_failed"
	ReasonInvalidGeneration = "invalid_generation"
	ReasonInvalidPool       = "invalid_pool"
	ReasonInvalidTime       = "invalid_time"
	ReasonInvalidMaxAge     = "invalid_max_age"
	ReasonIncomplete        = "incomplete_evidence"
	ReasonInvalidEvidence   = "invalid_evidence"
	ReasonPoolChanged       = "pool_changed"
	ReasonGenerationChanged = "generation_changed"
	ReasonWrongScope        = "wrong_scope"
	ReasonStale             = "stale_evidence"
	ReasonHealthy           = "healthy_candidate"
	ReasonUnconfirmed       = "failure_unconfirmed"
)

func validID(id string) bool {
	return id != "" && len(id) <= 256 && strings.TrimSpace(id) == id && !strings.ContainsAny(id, "\x00\r\n")
}

// PoolID hashes a sorted, length-delimited copy of opaque candidate IDs. It does
// not mutate the caller's pool. Empty, duplicate and malformed IDs are rejected.
func PoolID(candidates []string) (string, error) {
	if len(candidates) == 0 {
		return "", errors.New("enabled candidate pool is empty")
	}
	ids := append([]string(nil), candidates...)
	sort.Strings(ids)
	h := sha256.New()
	h.Write([]byte("personalroute-pool-v1\x00"))
	var size [8]byte
	for i, id := range ids {
		if !validID(id) || i > 0 && ids[i-1] == id {
			return "", errors.New("enabled candidate IDs must be unique and nonempty")
		}
		binary.BigEndian.PutUint64(size[:], uint64(len(id)))
		h.Write(size[:])
		h.Write([]byte(id))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Evaluate is stateless and fails closed unless the user disabled personal or
// every enabled candidate has one fresh explicit independent path failure.
// The caller must pass its authoritative full pool and current generations;
// this function cannot discover omitted nodes or reconstruct membership history.
func Evaluate(in Input) Decision {
	deny := func(reason string) Decision { return Decision{Reason: reason} }
	if in.ManualDisabled {
		return Decision{DirectAllowed: true, Reason: ReasonManualDisabled}
	}
	if !validID(in.Generation.Run) || !validID(in.Generation.Network) || !validID(in.Generation.Probe) {
		return deny(ReasonInvalidGeneration)
	}
	pool, err := PoolID(in.Candidates)
	if err != nil {
		return deny(ReasonInvalidPool)
	}
	if in.Now.IsZero() {
		return deny(ReasonInvalidTime)
	}
	age := in.MaxAge
	if age == 0 {
		age = DefaultMaxAge
	}
	if age < 0 || age > DefaultMaxAge {
		return deny(ReasonInvalidMaxAge)
	}
	if len(in.Observations) != len(in.Candidates) {
		return deny(ReasonIncomplete)
	}
	observed := make(map[string]Observation, len(in.Observations))
	for _, o := range in.Observations {
		if !validID(o.CandidateID) {
			return deny(ReasonInvalidEvidence)
		}
		if _, exists := observed[o.CandidateID]; exists {
			return deny(ReasonInvalidEvidence)
		}
		observed[o.CandidateID] = o
	}
	for _, id := range in.Candidates {
		o, exists := observed[id]
		if !exists {
			return deny(ReasonIncomplete)
		}
		if o.PoolID != pool {
			return deny(ReasonPoolChanged)
		}
		if o.Generation != in.Generation {
			return deny(ReasonGenerationChanged)
		}
		if o.Scope != IndependentHealth {
			return deny(ReasonWrongScope)
		}
		if o.StartedAt.IsZero() || o.FinishedAt.IsZero() || o.FinishedAt.Before(o.StartedAt) || o.StartedAt.After(in.Now) || o.FinishedAt.After(in.Now) {
			return deny(ReasonInvalidTime)
		}
		if in.Now.Sub(o.StartedAt) >= age || in.Now.Sub(o.FinishedAt) >= age {
			return deny(ReasonStale)
		}
		if o.Outcome == Healthy {
			return deny(ReasonHealthy)
		}
		if o.Outcome != PathFailed {
			return deny(ReasonUnconfirmed)
		}
	}
	return Decision{DirectAllowed: true, Reason: ReasonAllFailed}
}
