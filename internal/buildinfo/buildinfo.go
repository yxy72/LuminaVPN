// Package buildinfo exposes only public, reproducible build identity.
package buildinfo

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// Version is the single source for the CLI and distribution package names.
const Version = "0.2.0-preview.1"

type Info struct {
	Version   string `json:"version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	GoVersion string `json:"go_version"`
	Revision  string `json:"revision,omitempty"`
	Modified  *bool  `json:"modified,omitempty"`
}

func Current() Info {
	i := Info{Version: Version, OS: runtime.GOOS, Arch: runtime.GOARCH, GoVersion: runtime.Version()}
	if b, ok := debug.ReadBuildInfo(); ok {
		for _, s := range b.Settings {
			switch s.Key {
			case "vcs.revision":
				// Do not copy arbitrary build settings, paths or linker arguments.
				if (len(s.Value) == 40 || len(s.Value) == 64) && strings.Trim(s.Value, "0123456789abcdef") == "" {
					i.Revision = s.Value
				}
			case "vcs.modified":
				if s.Value == "true" || s.Value == "false" {
					modified := s.Value == "true"
					i.Modified = &modified
				}
			}
		}
	}
	return i
}
