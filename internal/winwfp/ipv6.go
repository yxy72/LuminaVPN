package winwfp

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

// IPv6Spec is an independent, machine-wide outbound protection resource. It is
// not tied to the optional VPN adapter and never changes interface settings.
type IPv6Spec struct {
	Provider string `json:"provider"`
	Sublayer string `json:"sublayer"`
	Outbound string `json:"outbound"`
	Forward  string `json:"forward"`
}
type IPv6Status struct{ Provider, Sublayer, Outbound, Forward bool }

func (s IPv6Status) Complete() bool { return s.Provider && s.Sublayer && s.Outbound && s.Forward }
func (s IPv6Status) Empty() bool    { return !s.Provider && !s.Sublayer && !s.Outbound && !s.Forward }
func NewIPv6() (IPv6Spec, error) {
	keys := make([]string, 4)
	for i := range keys {
		b := make([]byte, 16)
		if _, e := rand.Read(b); e != nil {
			return IPv6Spec{}, e
		}
		b[6] = (b[6] & 15) | 64
		b[8] = (b[8] & 63) | 128
		h := hex.EncodeToString(b)
		keys[i] = "{" + h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:] + "}"
	}
	s := IPv6Spec{keys[0], keys[1], keys[2], keys[3]}
	return s, s.Validate()
}
func (s IPv6Spec) Validate() error {
	seen := map[string]bool{}
	for _, k := range []string{s.Provider, s.Sublayer, s.Outbound, s.Forward} {
		if !guid.MatchString(k) || seen[k] {
			return errors.New("invalid global IPv6 ownership key")
		}
		seen[k] = true
	}
	return nil
}
func (s IPv6Spec) Name() string { return "NetLaunch-IPv6-" + s.Provider }
