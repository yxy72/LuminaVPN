//go:build windows

package winstate

import (
	"encoding/json"
	"errors"
	"netlaunch/internal/securefile"
	"netlaunch/internal/winnet"
	"netlaunch/internal/winwfp"
	"path/filepath"
	"regexp"
	"time"
)

type NativeBackend struct{}

func (NativeBackend) BootID() (string, error)                      { return winnet.BootID() }
func (NativeBackend) Lookup(r winnet.Route) (*winnet.Route, error) { return winnet.Lookup(r) }
func (NativeBackend) Add(r winnet.Route) (winnet.Route, error)     { return winnet.Add(r) }
func (NativeBackend) Delete(r winnet.Route) error                  { return winnet.Delete(r) }
func (NativeBackend) Adapter(guid string) (winnet.Adapter, error) {
	items, e := winnet.Adapters()
	if e != nil {
		return winnet.Adapter{}, e
	}
	for _, a := range items {
		if a.GUID == guid {
			return a, nil
		}
	}
	return winnet.Adapter{}, winnet.ErrAdapterAbsent
}
func (NativeBackend) DNS(a winnet.Adapter, ipv6 bool) (winnet.DNSSettings, error) {
	return winnet.ConfiguredDNSFamily(a, ipv6)
}
func (NativeBackend) SetDNS(a winnet.Adapter, d winnet.DNSSettings) error {
	return winnet.SetConfiguredDNS(a, d)
}

type NativeStorage struct {
	Files          securefile.AdminStore
	RunID          string
	RetainEvidence bool
}

var runID = regexp.MustCompile(`^netlaunch-[a-z0-9]{16,64}$`)

func (s NativeStorage) valid() error {
	if !runID.MatchString(s.RunID) {
		return errors.New("invalid native run identifier")
	}
	return nil
}
func (s NativeStorage) Lock() (func(), error) {
	if e := s.valid(); e != nil {
		return nil, e
	}
	return s.Files.Lock(filepath.Join(s.RunID, "network.lock"), 30*time.Second)
}
func (s NativeStorage) Load() (Journal, error) {
	var j Journal
	if e := s.valid(); e != nil {
		return j, e
	}
	b, e := s.Files.Read(filepath.Join(s.RunID, "network.json"), 4<<20)
	if e != nil {
		return j, e
	}
	if e = json.Unmarshal(b, &j); e != nil {
		return j, errors.New("invalid administrator network journal")
	}
	return j, nil
}
func (s NativeStorage) Save(j Journal) error {
	if e := s.valid(); e != nil {
		return e
	}
	if s.RetainEvidence {
		b, err := json.Marshal(j)
		if err != nil {
			return err
		}
		if len(b) > 4<<20 {
			return errors.New("service recovery evidence reached bounded journal capacity")
		}
	}
	return s.Files.Write(filepath.Join(s.RunID, "network.json"), j)
}

func (NativeBackend) Addresses() ([]winnet.Address, error) { return winnet.Addresses() }
func (NativeBackend) LookupAddress(a winnet.Address) (*winnet.Address, error) {
	return winnet.LookupAddress(a)
}
func (NativeBackend) AddAddress(a winnet.Address) (winnet.Address, error) {
	return winnet.AddAddress(a)
}
func (NativeBackend) DeleteAddress(a winnet.Address) error { return winnet.DeleteAddress(a) }
func (NativeBackend) MTU(a winnet.Adapter) (uint32, error) { return winnet.MTU(a) }
func (NativeBackend) SetMTU(a winnet.Adapter, before, after uint32) error {
	return winnet.SetMTU(a, before, after)
}

func (NativeBackend) InspectGuard(s winwfp.Spec) (winwfp.Status, error) { return winwfp.Inspect(s) }
func (NativeBackend) AddGuard(s winwfp.Spec) error                      { return winwfp.Add(s) }
func (NativeBackend) RemoveGuard(s winwfp.Spec) error                   { return winwfp.Remove(s) }

func (NativeBackend) InspectIPv6(s winwfp.IPv6Spec) (winwfp.IPv6Status, error) {
	return winwfp.InspectIPv6(s)
}
func (NativeBackend) AddIPv6(s winwfp.IPv6Spec) error    { return winwfp.AddIPv6(s) }
func (NativeBackend) RemoveIPv6(s winwfp.IPv6Spec) error { return winwfp.RemoveIPv6(s) }
