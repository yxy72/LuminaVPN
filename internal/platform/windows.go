//go:build windows

package platform

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"netlaunch/internal/winnet"
)

// Ordinary builds remain gated. The home preview keeps a bounded lifecycle.
func Supported() bool { return WindowsValidationBuild || WindowsHomeBuild || WindowsClientBuild }
func Discover() (Network, error) {
	n, e := winnet.Discover()
	if e != nil {
		return Network{}, e
	}
	return Network{Interface: n.Adapter.Name, Address: n.Address, Gateway: n.Gateway, Service: n.Adapter.GUID}, nil
}
func Candidates() (string, string, error) {
	all, e := winnet.Adapters()
	if e != nil {
		return "", "", e
	}
	names := map[string]bool{}
	for _, a := range all {
		names[a.Name] = true
	}
	for i := 0; i < 8; i++ {
		b := make([]byte, 8)
		if _, e = rand.Read(b); e != nil {
			return "", "", e
		}
		id := hex.EncodeToString(b)
		vpn, tun := "NL-VPN-"+id, "NL-TUN-"+id
		if !names[vpn] && !names[tun] {
			return vpn, tun, nil
		}
	}
	return "", "", errors.New("could not reserve candidate names")
}
func ForeignVPN() bool { found, e := foreignOpenConnect(); return e != nil || found }
func CheckConflicts(Network) error {
	a, e := winnet.Adapters()
	if e != nil {
		return e
	}
	r, e := winnet.Routes()
	if e != nil {
		return e
	}
	virtual := map[uint64]bool{}
	for _, dev := range a {
		if !dev.Hardware && dev.Type != 24 && dev.Up {
			virtual[dev.LUID] = true
		}
	}
	for _, route := range r {
		if virtual[route.InterfaceLUID] && (route.Prefix == "0.0.0.0/0" || route.Prefix == "0.0.0.0/1" || route.Prefix == "128.0.0.0/1") {
			return errors.New("another virtual adapter captures IPv4; stop it before up")
		}
	}
	return nil
}
