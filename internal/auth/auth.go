package auth

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
)

type Session struct {
	Cookie      string    `json:"cookie"`
	Host        string    `json:"host"`
	Fingerprint string    `json:"fingerprint"`
	Created     time.Time `json:"created"`
}
type cached struct {
	Server   string  `json:"server"`
	Endpoint string  `json:"endpoint"`
	Session  Session `json:"session"`
}

const MaxAge = 2 * time.Hour

var fingerprint = regexp.MustCompile(`^(?:sha256|pin-sha256):[A-Za-z0-9+/=]+$`)

func Parse(data string, vpn policy.VPN) (Session, error) {
	bad := errors.New("local authentication response failed validation")
	if len(data) > 128<<10 {
		return Session{}, bad
	}
	values := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		// Windows native stdout may use CRLF. Remove only the line ending;
		// embedded control characters still fail normal session validation.
		line = strings.TrimSuffix(line, "\r")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "COOKIE", "HOST", "CONNECT_URL", "FINGERPRINT", "RESOLVE":
		default:
			continue
		}
		if _, exists := values[k]; exists {
			return Session{}, bad
		}
		if v != "" {
			if len(v) < 2 || v[0] != '\'' || v[len(v)-1] != '\'' || strings.Contains(v[1:len(v)-1], "'") {
				return Session{}, bad
			}
			v = v[1 : len(v)-1]
		}
		values[k] = v
	}
	u, e := url.Parse(vpn.Server)
	if e != nil {
		return Session{}, bad
	}
	if values["HOST"] != u.Hostname() {
		connected, e := url.Parse(values["CONNECT_URL"])
		if e != nil || values["HOST"] != vpn.EndpointIPv4 || connected.Scheme != "https" || connected.Host != u.Host || connected.User != nil || values["RESOLVE"] != u.Hostname()+":"+vpn.EndpointIPv4 {
			return Session{}, bad
		}
	}
	if raw := values["CONNECT_URL"]; raw != "" {
		v, e := url.Parse(raw)
		if e != nil || v.Scheme != "https" || v.Host != u.Host || v.User != nil {
			return Session{}, bad
		}
	}
	s := Session{values["COOKIE"], u.Hostname(), values["FINGERPRINT"], time.Now()}
	if e := s.Validate(vpn); e != nil {
		return Session{}, e
	}
	return s, nil
}
func (s Session) Validate(vpn policy.VPN) error {
	u, e := url.Parse(vpn.Server)
	if e != nil || s.Host != u.Hostname() || len(s.Cookie) == 0 || len(s.Cookie) > 65536 || !fingerprint.MatchString(s.Fingerprint) {
		return errors.New("invalid local VPN session")
	}
	for _, r := range s.Cookie {
		if r < 32 || r == 127 {
			return errors.New("invalid local VPN session")
		}
	}
	return nil
}
func Save(dir string, vpn policy.VPN, s Session) error {
	if e := s.Validate(vpn); e != nil {
		return e
	}
	return securefile.Write(filepath.Join(dir, "session.json"), cached{vpn.Server, vpn.EndpointIPv4, s})
}
func Load(dir string, vpn policy.VPN) (Session, bool) {
	p := filepath.Join(dir, "session.json")
	b, e := securefile.Read(p, 128<<10, true)
	if e != nil {
		return Session{}, false
	}
	var c cached
	if json.Unmarshal(b, &c) != nil || c.Server != vpn.Server || c.Endpoint != vpn.EndpointIPv4 || c.Session.Validate(vpn) != nil {
		return Session{}, false
	}
	age := time.Since(c.Session.Created)
	if age < 0 || age > MaxAge {
		_ = os.Remove(p)
		return Session{}, false
	}
	return c.Session, true
}
