package application

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"netlaunch/internal/platform"
)

func TestMacEnvironmentConflictCheckWaitsForOwnRunState(t *testing.T) {
	for _, tc := range []struct {
		name, phase                string
		unreadable, lost, takeover bool
		busy, canCheck             bool
	}{
		{name: "no run", canCheck: true},
		{name: "saved stopped", phase: "stopped", canCheck: true},
		{name: "contradictory stopped report", phase: "stopped", takeover: true},
		{name: "running", phase: "ready"},
		{name: "unreadable run", unreadable: true},
		{name: "lost run reference", phase: "ready", lost: true},
		{name: "local operation", busy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, report := macBackendFixture(t)
			w := d.localWorkspace
			if tc.phase != "" {
				run := makeMacReport(t, tc.phase)
				run.status.TakeoverActive = tc.takeover
				report.Store(&run)
			}
			if tc.unreadable {
				report.Store(&macRunReport{present: true})
			}
			if tc.lost {
				w.network.observe(d.Profile)
				report.Store(&macRunReport{})
			}
			if tc.busy {
				w.active = make(chan struct{})
				t.Cleanup(func() { close(w.active) })
			}
			invoked := false
			check, err := w.checkMacEnvironment(t.Context(), func() (platform.Network, error) {
				return platform.Network{}, nil
			}, func(platform.Network) error {
				invoked = true
				return platform.ErrSystemProxyConflict
			}, func() bool { return false })
			if err != nil || invoked != tc.canCheck || (check.State == "failed") != tc.canCheck {
				t.Fatalf("unexpected conflict check: %#v, called=%t, err=%v", check, invoked, err)
			}
			if !tc.canCheck && check.State != "not_checked" {
				t.Fatal("uncertain own-run state was classified", check)
			}
		})
	}
}

func TestMacEnvironmentDiscardsChecksIfRunAppearsDuringObservation(t *testing.T) {
	for _, duringDiscovery := range []bool{true, false} {
		d, report := macBackendFixture(t)
		run := makeMacReport(t, "managed")
		invoked := false
		check, err := d.localWorkspace.checkMacEnvironment(t.Context(), func() (platform.Network, error) {
			if duringDiscovery {
				report.Store(&run)
			}
			return platform.Network{}, nil
		}, func(platform.Network) error {
			invoked = true
			report.Store(&run)
			return platform.ErrTunnelDefaultConflict
		}, func() bool { return false })
		if err != nil || check.State != "not_checked" || invoked == duringDiscovery {
			t.Fatalf("racing run should withhold conflict result: %#v, called=%t, err=%v", check, invoked, err)
		}
	}
}

func TestMacEnvironmentStopsBeforeReadingConflictsOnCancellation(t *testing.T) {
	d, _ := macBackendFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	_, err := d.localWorkspace.checkMacEnvironment(ctx, func() (platform.Network, error) {
		cancel()
		return platform.Network{}, nil
	}, func(platform.Network) error {
		t.Fatal("cancelled discovery still queried conflicts")
		return nil
	}, func() bool { return false })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestMacEnvironmentClassifiesAndRedactsNativeFindings(t *testing.T) {
	const private = "unpublished.local /private/path 192.0.2.44"
	d, _ := macBackendFixture(t)
	for _, tc := range []struct {
		discovery error
		conflict  error
		vpn       bool
		state     string
		message   string
	}{
		{errors.New(private), nil, false, "warning", "物理 IPv4"},
		{nil, errors.New(private), false, "warning", "未能读取"},
		{nil, platform.ErrSystemProxyConflict, false, "failed", "PAC"},
		{nil, platform.ErrTunnelDefaultConflict, false, "failed", "分段默认路由"},
		{nil, nil, true, "failed", "OpenConnect"},
		{nil, nil, false, "passed", "本次检查未发现"},
	} {
		check, err := d.localWorkspace.checkMacEnvironment(t.Context(), func() (platform.Network, error) {
			return platform.Network{Service: private}, tc.discovery
		}, func(platform.Network) error { return tc.conflict }, func() bool { return tc.vpn })
		if err != nil || check.State != tc.state || !strings.Contains(check.Message, tc.message) || strings.Contains(check.Message, private) {
			t.Fatalf("unexpected public diagnosis: %#v, %v", check, err)
		}
	}
}

func TestMacEnvironmentReportsDesktopCapabilityAndPendingPrivilegedChecks(t *testing.T) {
	d, report := macBackendFixture(t)
	d.Now = time.Now
	run := makeMacReport(t, "managed")
	report.Store(&run)
	result, err := d.Environment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	env := result.(map[string]any)
	if env["read_only"] != true || env["ready_for_start"] != false {
		t.Fatal("environment read must not authorize startup", env)
	}
	states := map[string]any{}
	for _, entry := range env["checks"].([]any) {
		row := entry.(map[string]any)
		states[row["id"].(string)] = row["state"]
	}
	if states["desktop_lifecycle"] != "passed" || states["privileged_listeners"] != "not_checked" || states["network_conflicts"] != "not_checked" {
		t.Fatal("desktop capability and unchecked conditions were conflated", states)
	}
}
