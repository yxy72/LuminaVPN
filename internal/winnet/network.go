// Package winnet keeps Windows adapter identity and route policy independent
// of command output, display language and the current global default route.
package winnet

import (
	"errors"
	"net/netip"
	"sort"
)

type Adapter struct {
	Index     uint32   `json:"index"`
	LUID      uint64   `json:"luid"`
	Name      string   `json:"name"`
	GUID      string   `json:"guid"`
	Type      uint32   `json:"type"`
	Up        bool     `json:"up"`
	Hardware  bool     `json:"hardware"`
	Metric    uint32   `json:"metric"`
	Addresses []string `json:"addresses"`
	DNS       []string `json:"effective_dns"`
}

type Route struct {
	InterfaceIndex    uint32 `json:"interface_index"`
	InterfaceLUID     uint64 `json:"interface_luid"`
	Prefix            string `json:"prefix"`
	NextHop           string `json:"next_hop"`
	Metric            uint32 `json:"metric"`
	Protocol          uint32 `json:"protocol"`
	Origin            uint32 `json:"origin"`
	ValidLifetime     uint32 `json:"valid_lifetime"`
	PreferredLifetime uint32 `json:"preferred_lifetime"`
	SitePrefixLength  uint8  `json:"site_prefix_length"`
	Loopback          bool   `json:"loopback"`
	AutoConfigure     bool   `json:"auto_configure"`
	Publish           bool   `json:"publish"`
	Immortal          bool   `json:"immortal"`
}

type Physical struct {
	Adapter Adapter `json:"adapter"`
	Address string  `json:"address"`
	Gateway string  `json:"gateway"`
}

func usableIPv4(s string) bool {
	a, e := netip.ParseAddr(s)
	return e == nil && a.Is4() && a.IsGlobalUnicast() && !a.IsLinkLocalUnicast()
}

// SelectPhysical ignores virtual adapters even when a TUN owns a lower-metric
// default. Equal-cost physical exits are ambiguous and require user selection.
func SelectPhysical(adapters []Adapter, routes []Route) (Physical, error) {
	type candidate struct {
		network Physical
		metric  uint64
	}
	var choices []candidate
	for _, a := range adapters {
		if !a.Up || !a.Hardware || a.Index == 0 || a.LUID == 0 || (a.Type != 6 && a.Type != 71) {
			continue
		}
		addresses := append([]string(nil), a.Addresses...)
		sort.Strings(addresses)
		address := ""
		for _, v := range addresses {
			if usableIPv4(v) {
				address = v
				break
			}
		}
		if address == "" {
			continue
		}
		for _, r := range routes {
			if r.Prefix != "0.0.0.0/0" || r.InterfaceIndex != a.Index || r.InterfaceLUID != a.LUID || !usableIPv4(r.NextHop) || r.Loopback {
				continue
			}
			choices = append(choices, candidate{Physical{a, address, r.NextHop}, uint64(a.Metric) + uint64(r.Metric)})
		}
	}
	if len(choices) == 0 {
		return Physical{}, errors.New("no active physical IPv4 exit")
	}
	sort.Slice(choices, func(i, j int) bool { return choices[i].metric < choices[j].metric })
	if len(choices) > 1 && choices[0].metric == choices[1].metric {
		return Physical{}, errors.New("multiple equal-cost physical exits")
	}
	return choices[0].network, nil
}

func SameKey(a, b Route) bool {
	return a.InterfaceIndex == b.InterfaceIndex && a.InterfaceLUID == b.InterfaceLUID && a.Prefix == b.Prefix && a.NextHop == b.NextHop
}

// OwnedEqual deliberately includes all writable attributes. Dynamic age is
// omitted. Recovery must additionally require its durable absent-before-add
// journal; a route that merely matches these values is not proof of ownership.
func OwnedEqual(a, b Route) bool { return a == b }

func managedRoute(r Route) error {
	p, e := netip.ParsePrefix(r.Prefix)
	if e != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() == 0 || (!usableIPv4(p.Addr().String()) && r.Prefix != "0.0.0.0/1") {
		return errors.New("managed route requires canonical non-default unicast IPv4 prefix")
	}
	h, e := netip.ParseAddr(r.NextHop)
	if e != nil || !h.Is4() || (!h.IsUnspecified() && !usableIPv4(r.NextHop)) {
		return errors.New("invalid route next hop")
	}
	if r.InterfaceIndex == 0 || r.InterfaceLUID == 0 || r.Protocol != 3 || r.Origin != 0 || r.ValidLifetime != ^uint32(0) || r.PreferredLifetime != ^uint32(0) || r.SitePrefixLength != 0 || r.Loopback || r.AutoConfigure || r.Publish || r.Immortal {
		return errors.New("invalid managed route attributes")
	}
	return nil
}

func NewRoute(a Adapter, prefix, nextHop string, metric uint32) (Route, error) {
	r := Route{InterfaceIndex: a.Index, InterfaceLUID: a.LUID, Prefix: prefix, NextHop: nextHop, Metric: metric, Protocol: 3, ValidLifetime: ^uint32(0), PreferredLifetime: ^uint32(0)}
	return r, managedRoute(r)
}

func (r Route) Validate() error { return managedRoute(r) }

// NewCaptureRoute creates one of the two IPv4 halves only on a new virtual
// TUN. The real physical default is retained for explicitly bound exits.
func NewCaptureRoute(a Adapter, prefix string) (Route, error) {
	if a.Hardware || a.Type != 53 || a.GUID == "" || (prefix != "0.0.0.0/1" && prefix != "128.0.0.0/1") {
		return Route{}, errors.New("capture route requires a virtual TUN and an IPv4 half")
	}
	return NewRoute(a, prefix, "0.0.0.0", 8)
}
