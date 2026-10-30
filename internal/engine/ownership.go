package engine

import (
	"errors"
	"strings"

	"netlaunch/internal/platform"
)

// A planned entry is recoverable only if the absent-before-add journal and
// kernel attributes agree. Matching only the destination is never sufficient.
func ownedRouteMatches(entry OwnedRoute, actual platform.Route) bool {
	if entry.State == "removed" || !keyMatch(entry.Route, actual) || entry.Route.Interface != actual.Interface {
		return false
	}
	if entry.State == "applied" {
		return sameRoute(entry.Route, actual)
	}
	if entry.State != "planned" || !strings.Contains(actual.Flags, "S") {
		return false
	}
	if entry.Route.Scoped {
		return !strings.Contains(actual.Flags, "G")
	}
	return actual.Gateway == entry.Route.Gateway && strings.Contains(actual.Flags, "G") && strings.Contains(actual.Flags, "H")
}
func keyMatch(a, b platform.Route) bool {
	return a.Prefix == b.Prefix && a.Scoped == b.Scoped && (!a.Scoped || a.Interface == b.Interface)
}
func sameRoute(a, b platform.Route) bool {
	return keyMatch(a, b) && a.Gateway == b.Gateway && a.Interface == b.Interface && strings.Contains(a.Flags, "G") == strings.Contains(b.Flags, "G") && strings.Contains(a.Flags, "S") == strings.Contains(b.Flags, "S")
}
func restoreDNS(current []string, change DNSChange) (bool, error) {
	value := strings.Join(current, ",")
	if value == strings.Join(change.Before, ",") {
		return false, nil
	}
	if value != strings.Join(change.After, ",") {
		return false, errors.New("DNS changed outside this run; original value not forced")
	}
	return true, nil
}
