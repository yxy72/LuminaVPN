package engine

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"netlaunch/internal/auth"
	"netlaunch/internal/dnswire"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
)

type Manifest struct {
	Service           *ServiceRunBinding    `json:"service,omitempty"`
	Mode              RunMode               `json:"mode,omitempty"`
	Channels          *policy.ChannelIntent `json:"channels,omitempty"`
	Version           int                   `json:"version"`
	Owner             int                   `json:"owner"`
	OwnerSID          string                `json:"owner_sid,omitempty"`
	Config            policy.Config         `json:"config"`
	Binding           policy.Binding        `json:"binding"`
	Network           platform.Network      `json:"network"`
	Executable        string                `json:"executable"`
	Created           time.Time             `json:"created"`
	ValidationTimeout time.Duration         `json:"validation_timeout,omitempty"`
}
type Child struct {
	Role     string             `json:"role"`
	PID      int                `json:"pid"`
	Birth    string             `json:"birth"`
	Args     []string           `json:"args"`
	GateArgs []string           `json:"gate_args"`
	Released bool               `json:"released"`
	Native   *platform.Identity `json:"native,omitempty"`
	LogName  string             `json:"log_name,omitempty"`
}
type OwnedRoute struct {
	Route          platform.Route `json:"route"`
	State          string         `json:"state"`
	InterfaceIndex int            `json:"interface_index"`
}
type DNSChange struct {
	Before []string `json:"before"`
	After  []string `json:"after"`
}
type VPNSession struct {
	PID        int    `json:"pid"`
	Interface  string `json:"interface"`
	Index      int    `json:"index"`
	Address    string `json:"address"`
	Generation string `json:"generation"`
	Bootstrap  bool   `json:"bootstrap"`
	WakeEpoch  string `json:"wake_epoch,omitempty"`
}
type State struct {
	DesiredChannels   *policy.ChannelIntent    `json:"desired_channels,omitempty"`
	ChannelGeneration uint64                   `json:"channel_generation,omitempty"`
	PersonalFallback  bool                     `json:"personal_fallback,omitempty"`
	AppliedChannels   *policy.ChannelIntent    `json:"applied_channels,omitempty"`
	AppliedGeneration uint64                   `json:"applied_generation,omitempty"`
	TakeoverActive    bool                     `json:"takeover_active,omitempty"`
	RunSpecDigest     string                   `json:"run_spec_digest,omitempty"`
	Channels          map[string]ChannelHealth `json:"channels,omitempty"`
	Version           int                      `json:"version"`
	Windows           *WindowsState            `json:"windows,omitempty"`
	Phase             string                   `json:"phase"`
	Updated           time.Time                `json:"updated"`
	Heartbeat         time.Time                `json:"heartbeat"`
	Runner            platform.Identity        `json:"runner"`
	Watcher           platform.Identity        `json:"watcher"`
	Manifest          Manifest                 `json:"manifest"`
	Children          []Child                  `json:"children"`
	Routes            []OwnedRoute             `json:"routes"`
	DNS               map[string]DNSChange     `json:"dns"`
	VPN               VPNSession               `json:"vpn"`
	Leases            []dnswire.Answer         `json:"leases"`
	Personal          string                   `json:"personal"`
	Error             string                   `json:"error,omitempty"`
	LastReady         time.Time                `json:"last_ready"`
	RecoveryReason    string                   `json:"recovery_reason,omitempty"`
}
type Status struct {
	DesiredChannels   *policy.ChannelIntent    `json:"desired_channels,omitempty"`
	AppliedChannels   *policy.ChannelIntent    `json:"applied_channels,omitempty"`
	ChannelGeneration uint64                   `json:"channel_generation,omitempty"`
	AppliedGeneration uint64                   `json:"applied_generation,omitempty"`
	TakeoverActive    bool                     `json:"takeover_active,omitempty"`
	PersonalFallback  bool                     `json:"personal_fallback,omitempty"`
	Channels          map[string]ChannelStatus `json:"channels,omitempty"`
	Lifecycle         string                   `json:"lifecycle,omitempty"`
	Phase             string                   `json:"phase"`
	Updated           time.Time                `json:"updated"`
	Company           string                   `json:"company"`
	Personal          string                   `json:"personal"`
	LastReady         time.Time                `json:"last_ready"`
	Error             string                   `json:"error,omitempty"`
	RecoveryReason    string                   `json:"recovery_reason,omitempty"`
	Experimental      bool                     `json:"experimental"`
}

func ReadManifest(run string) (Manifest, error) {
	return readManifest(run, false)
}

func readRecoveryManifest(run string) (Manifest, error) {
	return readManifest(run, true)
}

func readManifest(run string, recovery bool) (Manifest, error) {
	var m Manifest
	if e := ValidateRun(run); e != nil {
		return m, e
	}
	b, e := securefile.Read(filepath.Join(run, "manifest.json"), 1<<20, true)
	if e != nil {
		return m, e
	}
	if json.Unmarshal(b, &m) != nil || m.Version != 1 {
		return m, errors.New("invalid run manifest")
	}
	if m.ValidationTimeout != 0 && (m.ValidationTimeout < time.Second || m.ValidationTimeout > 12*time.Hour) {
		return m, errors.New("invalid validation timeout")
	}
	modeError := m.ValidateMode()
	if recovery {
		modeError = m.validateRecoveryMode()
	}
	if modeError != nil {
		return m, modeError
	}
	if e := validateOwner(run, m); e != nil {
		return m, e
	}
	return m, m.Config.ValidateForIntent(m.InitialChannels())
}
func ValidateRun(run string) error {
	abs, e := filepath.Abs(run)
	if e != nil || abs != run || filepath.Clean(run) != run || !strings.HasPrefix(filepath.Base(run), "netlaunch-") {
		return errors.New("invalid run path")
	}
	if e := securefile.CheckDir(run); e != nil {
		return e
	}
	return nil
}
func readJSON(path string, v any) error {
	b, e := securefile.Read(path, 4<<20, true)
	if e != nil {
		return e
	}
	if json.Unmarshal(b, v) != nil {
		return errors.New("invalid private state")
	}
	return nil
}
func readAuth(run string) (auth.Session, error) {
	m, e := ReadManifest(run)
	if e != nil {
		return auth.Session{}, e
	}
	b, e := securefile.Read(filepath.Join(run, "auth.json"), 768<<10, true)
	if e != nil {
		return auth.Session{}, e
	}
	defer clear(b)
	return auth.DecodeRuntime(m.Config.VPN, b)
}
