//go:build windows

package main

import (
	"netlaunch/internal/winnet"
	"testing"
)

func TestMutationCleanupAuthorityIsNarrow(t *testing.T) {
	a := winnet.Adapter{Index: 42, LUID: 4242, GUID: "fixture", Type: 53}
	r, e := winnet.NewRoute(a, "192.0.2.2/32", "0.0.0.0", 1)
	if e != nil {
		t.Fatal(e)
	}
	v := routeMutation{Original: r, Replacement: r}
	v.Replacement.Metric = 0
	if e = validateMutation(v, a); e != nil {
		t.Fatal(e)
	}
	for _, alter := range []func(*routeMutation, *winnet.Adapter){
		func(v *routeMutation, _ *winnet.Adapter) {
			v.Original.Prefix = "198.51.100.2/32"
			v.Replacement.Prefix = v.Original.Prefix
		},
		func(v *routeMutation, _ *winnet.Adapter) {
			v.Original.NextHop = "192.0.2.254"
			v.Replacement.NextHop = v.Original.NextHop
		},
		func(v *routeMutation, _ *winnet.Adapter) { v.Replacement.InterfaceLUID++ },
		func(v *routeMutation, _ *winnet.Adapter) { v.Replacement.InterfaceIndex++ },
		func(v *routeMutation, _ *winnet.Adapter) { v.Replacement.Protocol++ },
		func(v *routeMutation, _ *winnet.Adapter) { v.Replacement.Metric = 1 },
		func(v *routeMutation, _ *winnet.Adapter) { v.Original.Metric = 0 },
		func(_ *routeMutation, a *winnet.Adapter) { a.Hardware = true },
		func(_ *routeMutation, a *winnet.Adapter) { a.Type = 6 },
		func(_ *routeMutation, a *winnet.Adapter) { a.GUID = "" },
		func(_ *routeMutation, a *winnet.Adapter) { a.LUID++ },
	} {
		bad, wrong := v, a
		alter(&bad, &wrong)
		if validateMutation(bad, wrong) == nil {
			t.Fatal("mutation cleanup admitted a broader resource")
		}
	}
}
