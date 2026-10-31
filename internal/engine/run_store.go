package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
)

const currentStateVersion = 2

// Immutable input is stored once. The current binding/network belongs to the
// snapshot because reconnects may replace interfaces and physical adapters.
func immutableRunSpec(m Manifest) Manifest {
	m.Binding = policy.Binding{}
	m.Network = platform.Network{}
	return m
}

func runSpecDigest(m Manifest) string {
	raw, _ := json.Marshal(m)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

type runtimeManifest struct {
	Network platform.Network `json:"network"`
	Binding policy.Binding   `json:"binding"`
}

func stateRecord(s *State) (any, error) {
	if s.Version == 1 && s.RunSpecDigest == "" {
		return s, nil
	}
	if s.Version != currentStateVersion || s.RunSpecDigest == "" || runSpecDigest(immutableRunSpec(s.Manifest)) != s.RunSpecDigest {
		return nil, errors.New("immutable run specification changed or state version is unsupported")
	}
	// The explicit manifest shadows State.Manifest during JSON encoding. Native
	// resource intents remain in the same atomic state record, without config.
	return struct {
		*State
		Manifest runtimeManifest `json:"manifest"`
	}{s, runtimeManifest{s.Manifest.Network, s.Manifest.Binding}}, nil
}

func decodeState(raw []byte, readSpec func() ([]byte, error)) (State, error) {
	var s State
	if json.Unmarshal(raw, &s) != nil {
		return s, errors.New("invalid recovery state")
	}
	if s.Version == 1 && s.RunSpecDigest == "" {
		return s, nil
	}
	if s.Version != currentStateVersion || s.RunSpecDigest == "" {
		return s, errors.New("unsupported recovery state version")
	}
	var shape struct {
		Manifest map[string]json.RawMessage `json:"manifest"`
	}
	if json.Unmarshal(raw, &shape) != nil || len(shape.Manifest) != 2 || len(shape.Manifest["network"]) == 0 || string(shape.Manifest["network"]) == "null" || len(shape.Manifest["binding"]) == 0 || string(shape.Manifest["binding"]) == "null" {
		return s, errors.New("invalid runtime binding snapshot")
	}
	data, err := readSpec()
	if err != nil {
		return s, err
	}
	var spec Manifest
	if json.Unmarshal(data, &spec) != nil || spec.Version != 1 || spec.Network != (platform.Network{}) || spec.Binding != (policy.Binding{}) || runSpecDigest(spec) != s.RunSpecDigest {
		return s, errors.New("immutable run specification failed verification; preserve recovery files")
	}
	if err := spec.Config.Validate(); err != nil {
		return s, err
	}
	network, binding := s.Manifest.Network, s.Manifest.Binding
	s.Manifest = spec
	s.Manifest.Network, s.Manifest.Binding = network, binding
	return s, nil
}
