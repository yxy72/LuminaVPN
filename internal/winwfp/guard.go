// Package winwfp describes the narrow deny rules for a single owned VPN.
// It never changes a firewall profile, policy default or unrelated adapter.
package winwfp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"netlaunch/internal/winnet"
	"regexp"
	"strings"
)

type Spec struct {
	Sublayer   string         `json:"sublayer"`
	ForeignApp string         `json:"foreign_app"`
	NonTCP     string         `json:"non_tcp"`
	IPv6       string         `json:"ipv6"`
	Adapter    winnet.Adapter `json:"adapter"`
	Executable string         `json:"executable"`
	AppID      []byte         `json:"app_id"`
}
type Status struct{ Sublayer, ForeignApp, NonTCP, IPv6 bool }

func (s Status) Complete() bool { return s.Sublayer && s.ForeignApp && s.NonTCP && s.IPv6 }
func (s Status) Empty() bool    { return !s.Sublayer && !s.ForeignApp && !s.NonTCP && !s.IPv6 }

var guid = regexp.MustCompile(`^\{[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\}$`)

func New(a winnet.Adapter, exe string, app []byte) (Spec, error) {
	keys := make([]string, 4)
	for i := range keys {
		b := make([]byte, 16)
		if _, e := rand.Read(b); e != nil {
			return Spec{}, e
		}
		b[6] = (b[6] & 15) | 64
		b[8] = (b[8] & 63) | 128
		h := hex.EncodeToString(b)
		keys[i] = "{" + h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:] + "}"
	}
	s := Spec{keys[0], keys[1], keys[2], keys[3], a, exe, append([]byte(nil), app...)}
	return s, s.Validate()
}
func (s Spec) Validate() error {
	keys := map[string]bool{}
	for _, k := range []string{s.Sublayer, s.ForeignApp, s.NonTCP, s.IPv6} {
		if !guid.MatchString(k) || keys[k] {
			return errors.New("invalid WFP ownership key")
		}
		keys[k] = true
	}
	a := s.Adapter
	if a.Index == 0 || a.LUID == 0 || a.GUID == "" || a.Hardware || a.Type != 53 {
		return errors.New("WFP guard requires owned virtual VPN")
	}
	if len(s.Executable) < 4 || s.Executable[1:3] != `:\` || strings.ContainsAny(s.Executable, "\x00\r\n\"") || len(s.AppID) < 4 || len(s.AppID) > 65536 || len(s.AppID)%2 != 0 {
		return errors.New("invalid WFP application identity")
	}
	return nil
}
func Same(a, b Spec) bool {
	return a.Sublayer == b.Sublayer && a.ForeignApp == b.ForeignApp && a.NonTCP == b.NonTCP && a.IPv6 == b.IPv6 && winnet.SameAdapter(a.Adapter, b.Adapter) && a.Executable == b.Executable && bytes.Equal(a.AppID, b.AppID)
}
func (s Spec) Name() string { return "NetLaunch-" + s.Sublayer }
