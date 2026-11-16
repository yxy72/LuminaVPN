//go:build darwin

package engine

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"netlaunch/internal/dnswire"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
)

func TestOpenConnectHookCommandPreservesLiteralPath(t *testing.T) {
	for _, folder := range []string{"Application Support", "App's Support $(false); #"} {
		t.Run(folder, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), folder)
			if e := os.Mkdir(dir, 0700); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(dir, "vpn-hook")
			if e := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'hook-complete'\n"), 0700); e != nil {
				t.Fatal(e)
			}
			// Matches OpenConnect 9.21 script_config_tun's execl(/bin/sh, -c, script).
			command := strings.TrimPrefix(vpnScriptOption(path), "--script=")
			out, e := exec.Command("/bin/sh", "-c", command).CombinedOutput()
			if e != nil || string(out) != "hook-complete" {
				t.Fatal(string(out), e)
			}
		})
	}
}

func TestDarwinVPNHookRequiresCurrentReleasedAttempt(t *testing.T) {
	const path = "/owned/openconnect"
	prior := Child{Role: "vpn", PID: 100, Birth: "prior", Args: []string{path}, Released: true}
	active := Child{Role: "vpn", PID: 200, Birth: "active", Args: []string{path, "--non-inter"}, Released: true}
	dialIdentity := platform.Identity{PID: active.PID, Birth: active.Birth, Executable: path, Command: path + " --non-inter"}
	live := func(pid int) (platform.Identity, error) {
		if pid == prior.PID {
			return platform.Identity{PID: prior.PID, Birth: prior.Birth, Executable: path, Command: path}, nil
		}
		return dialIdentity, nil
	}
	state := State{Manifest: Manifest{Binding: policy.Binding{VPN: "utun5"}}, Children: []Child{prior, active}}
	if err := validateDarwinVPNHook(state, active.PID, "utun5", live); err != nil {
		t.Fatal(err)
	}
	if err := validateDarwinVPNHook(state, prior.PID, "utun5", live); err == nil {
		t.Fatal("historic live VPN attempt authorized a hook")
	}
	if err := validateDarwinVPNHook(state, active.PID, "utun6", live); err == nil {
		t.Fatal("different VPN interface authorized a hook")
	}
	dialIdentity.Birth = "reused"
	if err := validateDarwinVPNHook(state, active.PID, "utun5", live); err == nil {
		t.Fatal("reused VPN PID authorized a hook")
	}
	dialIdentity.Birth = active.Birth
	dialIdentity.Command = path + " --unexpected"
	if err := validateDarwinVPNHook(state, active.PID, "utun5", live); err == nil {
		t.Fatal("process with a different command authorized a hook")
	}
	dialIdentity.Command = path + " --non-inter"
	state.Children[1].Released = false
	if err := validateDarwinVPNHook(state, active.PID, "utun5", live); err == nil {
		t.Fatal("unreleased journal entry authorized a hook")
	}
	state.Children[1].Released = true
	off := policy.DefaultIntent()
	off.Company = false
	state.DesiredChannels = &off
	if err := validateDarwinVPNHook(state, active.PID, "utun5", live); err == nil {
		t.Fatal("disabled company intent authorized a hook")
	}
	retireDarwinVPNAttempt(&state)
	on := policy.DefaultIntent()
	state.DesiredChannels = &on
	if err := validateDarwinVPNHook(state, active.PID, "utun5", live); err == nil {
		t.Fatal("re-enabled company intent revived a retired VPN hook")
	}
}

func TestDarwinCompanyFenceRevokesBeforeCoreReadback(t *testing.T) {
	state := State{
		VPN:      VPNSession{Bootstrap: true},
		Leases:   []dnswire.Answer{{Domain: "example.test"}},
		Channels: map[string]ChannelHealth{"company": {}, "personal": {}},
	}
	persisted := false
	readbackFailure := errors.New("controller readback mismatch")
	err := fenceDarwinCompanyTraffic(&state, func() error {
		_, hasCompany := state.Channels["company"]
		if state.VPN.Bootstrap || len(state.Leases) != 0 || hasCompany {
			t.Fatal("company authority still live at journal write")
		}
		if _, hasPersonal := state.Channels["personal"]; !hasPersonal {
			t.Fatal("company fence changed personal health")
		}
		persisted = true
		return nil
	}, func() error {
		if !persisted {
			t.Fatal("core gate contacted before authority was fenced")
		}
		return readbackFailure
	})
	if !errors.Is(err, readbackFailure) {
		t.Fatalf("gate closure failure was lost: %v", err)
	}
	writeFailure := errors.New("journal unavailable")
	err = fenceDarwinCompanyTraffic(&state, func() error { return writeFailure }, func() error {
		t.Fatal("continued after durable fence failed")
		return nil
	})
	if !errors.Is(err, writeFailure) {
		t.Fatalf("journal failure was lost: %v", err)
	}
}

func TestDarwinGuardBlocksDanglingStopMarker(t *testing.T) {
	run := t.TempDir()
	if err := os.Symlink("missing", filepath.Join(run, "STOP")); err != nil {
		t.Fatal(err)
	}
	if err := guard(run, &State{Phase: "ready"}); err == nil {
		t.Fatal("invalid STOP marker authorized native mutation")
	}
}
