//go:build windows

package engine

import (
	"errors"
	"netlaunch/internal/auth"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	"netlaunch/internal/winwfp"
	"os"
	"path/filepath"
)

// SetChannels changes requested runtime intent, never the immutable run spec.
// Only the already-authorized run owner can access update/ReadManifest. The
// coordinator applies it asynchronously and publishes its generation.
func SetChannels(run string, intent policy.ChannelIntent) error {
	return update(run, func(s *State) error {
		if s.Manifest.Mode == "" {
			return errors.New("legacy run has no desktop channel control")
		}
		if e := guard(run, s); e != nil {
			return e
		}
		if e := s.Manifest.Config.ValidateForIntent(intent); e != nil {
			return e
		}
		if intent.Personal {
			var nodes []policy.Node
			if e := winRead(run, "nodes.json", &nodes); e != nil {
				return e
			}
			if _, e := policy.SanitizeNodes(nodes); e != nil {
				return errors.New("personal channel has no valid frozen node pool")
			}
		}
		if currentIntent(*s) == intent {
			return nil
		}
		s.DesiredChannels = &intent
		s.ChannelGeneration++
		s.Channels = nil
		return nil
	})
}
func readProtectedAuth(run string, vpn policy.VPN) (auth.Session, error) {
	b, e := readRunFile(run, "auth.json", 768<<10)
	if e != nil {
		return auth.Session{}, e
	}
	defer clear(b)
	return auth.DecodeRuntime(vpn, b)
}

// A desktop base does not require a company cookie. Missing, expired or
// undecryptable session data leaves only company authentication pending; file
// ownership/ACL/read failures remain bootstrap failures.
func stageDesktopAuth(run string, vpn policy.VPN) error {
	path := filepath.Join(run, "auth.json")
	return stageDesktopAuthWith(
		func() ([]byte, error) { return securefile.Read(path, 768<<10, true) },
		func(b []byte) (auth.Session, error) { return auth.DecodeRuntime(vpn, b) },
		func(s auth.Session) error { return writeProtectedAuth(run, vpn, s) },
		func() error { return os.Remove(path) },
	)
}
func stageDesktopAuthWith(read func() ([]byte, error), decode func([]byte) (auth.Session, error), write func(auth.Session) error, remove func() error) error {
	b, err := read()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer clear(b)
	s, decodeErr := decode(b)
	if decodeErr == nil {
		if err = write(s); err != nil {
			return err
		}
	}
	return remove()
}
func writeProtectedAuth(run string, vpn policy.VPN, s auth.Session) error {
	v, e := auth.EncodeRuntime(vpn, s)
	if e != nil {
		return e
	}
	if e = winWrite(run, "auth.json", v); e != nil {
		return e
	}
	return update(run, func(state *State) error {
		state.Windows.AuthExpires = s.Created.Add(auth.MaxAge)
		if state.Phase == "authentication_required" {
			state.Phase = "reconnecting"
			state.Error = ""
		}
		return nil
	})
}
func refreshProtectedAuth(run string, s State) (bool, error) {
	// The public run owner supplies an already DPAPI-protected envelope. The
	// coordinator re-protects in its own execution context before storing it.
	path := filepath.Join(run, "auth-refresh.json")
	b, e := securefile.Read(path, 768<<10, true)
	if errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	defer clear(b)
	fresh, e := auth.DecodeRuntime(s.Manifest.Config.VPN, b)
	if e != nil {
		return false, e
	}
	if e = writeProtectedAuth(run, s.Manifest.Config.VPN, fresh); e != nil {
		return false, e
	}
	if e = os.Remove(path); e != nil {
		return false, e
	}
	return true, nil
}
func ensureBaseIPv6(run string) error {
	return update(run, func(s *State) error {
		if e := guard(run, s); e != nil {
			return e
		}
		if s.Windows.IPv6Guard == nil {
			spec, e := winwfp.NewIPv6()
			if e != nil {
				return e
			}
			s.Windows.IPv6Guard = &spec
			if e = save(run, s); e != nil {
				return e
			}
		}
		m, e := networkManager(run)
		if e != nil {
			return e
		}
		return m.EnsureIPv6(*s.Windows.IPv6Guard)
	})
}
