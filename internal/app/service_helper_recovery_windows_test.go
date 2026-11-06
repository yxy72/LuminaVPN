//go:build windows

package app

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"netlaunch/internal/engine"
	"netlaunch/internal/winservice"
)

func TestServiceHelperSIDRejectsDenyOnlyMembership(t *testing.T) {
	for _, attributes := range []uint32{0, windows.SE_GROUP_USE_FOR_DENY_ONLY, windows.SE_GROUP_ENABLED | windows.SE_GROUP_USE_FOR_DENY_ONLY} {
		if serviceHelperSIDEnabled(attributes) {
			t.Fatal("disabled or deny-only SID authorized")
		}
	}
	if !serviceHelperSIDEnabled(windows.SE_GROUP_ENABLED | windows.SE_GROUP_MANDATORY) {
		t.Fatal("enabled service SID rejected")
	}
}

func TestServiceHelperRecoveryCallerCannotStartOrChangeRun(t *testing.T) {
	for _, action := range []winservice.LifecycleAction{winservice.PrepareLifecycle, winservice.ServeLifecycle, winservice.SetChannelsLifecycle} {
		calls := 0
		err := authorizeServiceHelperAction(action, func() error { calls++; return errors.New("main SID absent") })
		if err == nil || calls != 1 {
			t.Fatal("mutating action bypassed main service SID", action, err, calls)
		}
	}
	for _, action := range []winservice.LifecycleAction{winservice.RecoverLifecycle, winservice.StatusLifecycle, winservice.AbortPrepareLifecycle} {
		if err := authorizeServiceHelperAction(action, func() error { t.Fatal("recovery action required main SID"); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if err := authorizeServiceHelperAction("shell", func() error { t.Fatal("unknown action reached token check"); return nil }); err == nil {
		t.Fatal("unknown action accepted")
	}
}

func TestServiceHelperAbortRequiresExactUnpreparedDurableBinding(t *testing.T) {
	r, prepared := serviceHelperRecoveryFixture()
	ref := engine.ServicePreparationReference{ProfileID: r.ProfileID, BindingRunRef: r.BindingRunRef, ServiceInstance: r.ServiceInstance}
	unprepared := prepared
	unprepared.PreparedRunID, unprepared.SpecDigest = "", ""
	for _, mainRole := range []func() error{func() error { return nil }, func() error { return errMainServiceHelperSIDAbsent }} {
		if err := verifyUnpreparedServiceRunWith(ref, mainRole, func(string) (winservice.Binding, error) { return unprepared, nil }, func(string) (winservice.Binding, error) { return unprepared, nil }); err != nil {
			t.Fatal(err)
		}
	}
	for _, alter := range []func(*winservice.Binding){
		func(b *winservice.Binding) { b.PreparedRunID = prepared.PreparedRunID },
		func(b *winservice.Binding) { b.SpecDigest = prepared.SpecDigest },
		func(b *winservice.Binding) { b.RunRef = "other" },
		func(b *winservice.Binding) { b.ServiceInstance = "other" },
		func(b *winservice.Binding) { b.ProfileID = "other" },
		func(b *winservice.Binding) { b.ExecutorSID = "S-1-5-21-1" },
	} {
		bad := unprepared
		alter(&bad)
		if err := verifyUnpreparedServiceRunWith(ref, func() error { return nil }, func(string) (winservice.Binding, error) { return bad, nil }, func(string) (winservice.Binding, error) {
			t.Fatal("loader error changed principal")
			return unprepared, nil
		}); err == nil {
			t.Fatal("unprepared binding mismatch accepted")
		}
	}
	if err := verifyUnpreparedServiceRunWith(ref, func() error { return nil }, func(string) (winservice.Binding, error) { return winservice.Binding{}, errors.New("corrupt") }, func(string) (winservice.Binding, error) {
		t.Fatal("corrupt main binding used recovery role")
		return unprepared, nil
	}); err == nil {
		t.Fatal("corrupt binding accepted")
	}
	var decoded engine.ServicePreparationReference
	if decodeServiceHelperJSON([]byte(`{"profile_id":"profile","binding_run_ref":"ref","service_instance":"instance","run_path":"C:\\untrusted"}`), &decoded) == nil {
		t.Fatal("abort accepted arbitrary path")
	}
}

func serviceHelperRecoveryFixture() (engine.ServiceRunReference, winservice.Binding) {
	r := engine.ServiceRunReference{ProfileID: "profile", RunID: "netlaunch-" + strings.Repeat("a", 32), SpecDigest: strings.Repeat("b", 64), BindingRunRef: "run-ref", ServiceInstance: "service-instance"}
	b := winservice.Binding{ProfileID: r.ProfileID, PreparedRunID: r.RunID, SpecDigest: r.SpecDigest, RunRef: r.BindingRunRef, ServiceInstance: r.ServiceInstance, ExecutorSID: "S-1-5-18"}
	return r, b
}

func TestServiceHelperRecoveryBindingFallbackIsReadOnlyAndExact(t *testing.T) {
	r, b := serviceHelperRecoveryFixture()
	for _, action := range []winservice.LifecycleAction{winservice.ServeLifecycle, winservice.SetChannelsLifecycle, winservice.RecoverLifecycle, winservice.StatusLifecycle} {
		calls := 0
		err := verifyBoundServiceRunWith(r, action, func() error { return errMainServiceHelperSIDAbsent }, func(string) (winservice.Binding, error) {
			t.Fatal("recovery caller reached main loader")
			return b, nil
		}, func(profile string) (winservice.Binding, error) {
			calls++
			if profile != r.ProfileID {
				t.Fatal(profile)
			}
			return b, nil
		})
		if serviceHelperRecoveryAction(action) {
			if err != nil || calls != 1 {
				t.Fatal("exact recovery binding rejected", action, err, calls)
			}
		} else if err == nil || calls != 0 {
			t.Fatal("recovery loader used for mutating action", action, err, calls)
		}
	}
	for _, change := range []func(*winservice.Binding){
		func(v *winservice.Binding) { v.ProfileID = "other" },
		func(v *winservice.Binding) { v.PreparedRunID = "netlaunch-" + strings.Repeat("c", 32) },
		func(v *winservice.Binding) { v.SpecDigest = strings.Repeat("d", 64) },
		func(v *winservice.Binding) { v.RunRef = "other-ref" },
		func(v *winservice.Binding) { v.ServiceInstance = "other-instance" },
		func(v *winservice.Binding) { v.ExecutorSID = "S-1-5-21-1" },
	} {
		bad := b
		change(&bad)
		if err := verifyBoundServiceRunWith(r, winservice.RecoverLifecycle, func() error { return errMainServiceHelperSIDAbsent }, func(string) (winservice.Binding, error) {
			t.Fatal("recovery caller reached main loader")
			return b, nil
		}, func(string) (winservice.Binding, error) { return bad, nil }); err == nil {
			t.Fatal("different recovery binding accepted")
		}
	}
	if err := verifyBoundServiceRunWith(r, winservice.StatusLifecycle, func() error { return nil }, func(string) (winservice.Binding, error) { return b, nil }, func(string) (winservice.Binding, error) { t.Fatal("unnecessary recovery fallback"); return b, nil }); err != nil {
		t.Fatal(err)
	}
	if err := verifyBoundServiceRunWith(r, winservice.RecoverLifecycle, func() error { return nil }, func(string) (winservice.Binding, error) { return b, nil }, func(string) (winservice.Binding, error) { t.Fatal("unnecessary recovery fallback"); return b, nil }); err != nil {
		t.Fatal(err)
	}
}

func TestServiceHelperInvalidReferenceNeverLoadsRecoveryBinding(t *testing.T) {
	r, b := serviceHelperRecoveryFixture()
	for _, action := range []winservice.LifecycleAction{winservice.PrepareLifecycle, "shell"} {
		if err := verifyBoundServiceRunWith(r, action, func() error { t.Fatal("invalid action reached token check"); return nil }, func(string) (winservice.Binding, error) { t.Fatal("invalid action loaded binding"); return b, nil }, func(string) (winservice.Binding, error) {
			t.Fatal("invalid action loaded recovery binding")
			return b, nil
		}); err == nil {
			t.Fatal("invalid bound action accepted")
		}
	}
	r.RunID = "../run"
	if err := verifyBoundServiceRunWith(r, winservice.RecoverLifecycle, func() error { t.Fatal("invalid reference reached token check"); return nil }, func(string) (winservice.Binding, error) { t.Fatal("invalid reference loaded binding"); return b, nil }, func(string) (winservice.Binding, error) {
		t.Fatal("invalid reference loaded recovery binding")
		return b, nil
	}); err == nil {
		t.Fatal("invalid reference accepted")
	}
}

func TestServiceHelperLoaderErrorsNeverSwitchPrincipal(t *testing.T) {
	r, b := serviceHelperRecoveryFixture()
	for _, action := range []winservice.LifecycleAction{winservice.RecoverLifecycle, winservice.StatusLifecycle} {
		for _, failure := range []error{errors.New("corrupt binding"), errors.New("unknown state"), errors.New("unprotected enrollment")} {
			if err := verifyBoundServiceRunWith(r, action, func() error { return nil }, func(string) (winservice.Binding, error) { return winservice.Binding{}, failure }, func(string) (winservice.Binding, error) {
				t.Fatal("main loader error switched principal")
				return b, nil
			}); !errors.Is(err, failure) {
				t.Fatal(err)
			}
		}
		if err := verifyBoundServiceRunWith(r, action, func() error { return errors.New("token query unknown") }, func(string) (winservice.Binding, error) { t.Fatal("unknown role reached main loader"); return b, nil }, func(string) (winservice.Binding, error) {
			t.Fatal("unknown role reached recovery loader")
			return b, nil
		}); err == nil {
			t.Fatal("unknown token role accepted")
		}
		if err := verifyBoundServiceRunWith(r, action, func() error { return errMainServiceHelperSIDAbsent }, func(string) (winservice.Binding, error) { t.Fatal("wrong main loader"); return b, nil }, func(string) (winservice.Binding, error) {
			return winservice.Binding{}, errors.New("recovery SID or binding invalid")
		}); err == nil {
			t.Fatal("invalid recovery executor accepted")
		}
	}
}
