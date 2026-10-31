package app

import (
	"errors"
	"flag"
	"fmt"
	"runtime"

	"netlaunch/internal/buildinfo"
	"netlaunch/internal/platform"
)

type buildIdentity struct {
	buildinfo.Info
	Mode         string            `json:"mode"`
	Capabilities buildCapabilities `json:"capabilities"`
}

type buildCapabilities struct {
	OfflinePolicy            bool   `json:"offline_policy"`
	NativeLifecycle          bool   `json:"native_lifecycle"`
	Experimental             bool   `json:"experimental"`
	CompanyEgressGuard       string `json:"company_egress_guard"`
	DefaultSessionSeconds    int    `json:"default_session_seconds,omitempty"`
	MaximumSessionSeconds    int    `json:"maximum_session_seconds,omitempty"`
	ExplicitDeadlineRequired bool   `json:"explicit_deadline_required,omitempty"`
}

func currentBuildIdentity() buildIdentity {
	return describeBuild(buildinfo.Current(), runtime.GOOS, platform.WindowsHomeBuild, platform.WindowsValidationBuild)
}

func describeBuild(info buildinfo.Info, target string, home, validation bool) buildIdentity {
	b := buildIdentity{Info: info, Mode: "offline", Capabilities: buildCapabilities{OfflinePolicy: true, CompanyEgressGuard: "unavailable"}}
	switch target {
	case "darwin":
		b.Mode = "macos_experimental"
		b.Capabilities.NativeLifecycle, b.Capabilities.Experimental = true, true
		b.Capabilities.CompanyEgressGuard = "scoped_routes_and_bound_sockets"
	case "windows":
		switch {
		case home && validation:
			b.Mode = "invalid_windows_tags"
		case home:
			b.Mode = "windows_home"
			b.Capabilities.NativeLifecycle, b.Capabilities.Experimental = true, true
			b.Capabilities.DefaultSessionSeconds = 8 * 60 * 60
			b.Capabilities.MaximumSessionSeconds = 12 * 60 * 60
		case validation:
			b.Mode = "windows_validation"
			b.Capabilities.NativeLifecycle, b.Capabilities.Experimental = true, true
			b.Capabilities.MaximumSessionSeconds = 45 * 60
			b.Capabilities.ExplicitDeadlineRequired = true
		default:
			b.Mode = "windows_offline"
		}
		if b.Capabilities.NativeLifecycle {
			b.Capabilities.CompanyEgressGuard = "wfp_process_ipv4_tcp"
		}
	}
	return b
}

func (c CLI) version(args []string) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(c.Err)
	structured := fs.Bool("json", false, "include build identity, mode and compiled capabilities")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected version arguments")
	}
	if *structured {
		return c.json(currentBuildIdentity())
	}
	_, err := fmt.Fprintln(c.Out, Version)
	return err
}
