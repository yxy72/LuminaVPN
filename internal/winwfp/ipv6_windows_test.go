//go:build windows

package winwfp

import "testing"

func TestGlobalIPv6EncodingHasNoVPNOrAppDependency(t *testing.T) {
	s, e := NewIPv6()
	if e != nil {
		t.Fatal(e)
	}
	a, e := encodeIPv6(s)
	if e != nil {
		t.Fatal(e)
	}
	if a.provider.Key == a.sub.Key {
		t.Fatal("provider collision")
	}
	if !ipv6SublayerEqual(a.sub, a.sub) {
		t.Fatal("own sublayer readback failed")
	}
	normalizedSub := a.sub
	normalizedSub.Weight--
	if !ipv6SublayerEqual(normalizedSub, a.sub) {
		t.Fatal("BFE-normalized sublayer weight rejected")
	}
	for _, alter := range []func(*sublayer){
		func(v *sublayer) { v.Key = a.provider.Key },
		func(v *sublayer) { v.Provider = &a.sub.Key },
		func(v *sublayer) { v.Flags = 1 },
		func(v *sublayer) { v.ProviderData.Size = 1 },
		func(v *sublayer) { v.Display.Name = nil },
	} {
		changed := normalizedSub
		alter(&changed)
		if ipv6SublayerEqual(changed, a.sub) {
			t.Fatal("changed IPv6 ownership metadata accepted")
		}
	}
	for i, f := range a.filters {
		if f.Action.Type != 0x1001 || !sameProviderPointer(f.Provider, &a.provider.Key) {
			t.Fatal("IPv6 guard narrowed or unowned", i)
		}
		if i == 0 {
			if f.Count != 1 || f.Conditions == nil || f.Conditions.Key != flagsCondition || f.Conditions.Match != 8 || f.Conditions.Value.Type != 3 || f.Conditions.Value.Data != 1 {
				t.Fatal("local loopback exclusion missing")
			}
		} else if f.Count != 0 {
			t.Fatal("unsupported condition on forwarding layer")
		}
		if f.Layer == layer4 || f.Layer == layer6 {
			t.Fatal("VPN-scoped ALE layer reused")
		}
		if !ipv6FilterEqual(f, f) {
			t.Fatal("own filter readback failed")
		}
		changed := f
		changed.Action.Type = 0x1002
		if ipv6FilterEqual(changed, f) {
			t.Fatal("foreign filter edit accepted")
		}
		if i == 0 {
			changed = f
			foreignCondition := *f.Conditions
			foreignCondition.Match = 0
			changed.Conditions = &foreignCondition
			if ipv6FilterEqual(changed, f) {
				t.Fatal("loopback exclusion edit accepted")
			}
		}
	}
}
