package runtimebundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"netlaunch/internal/securefile"
)

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	Version     int    `json:"version"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Mihomo      string `json:"mihomo_version"`
	OpenConnect string `json:"openconnect_version"`
	Files       []File `json:"files"`
}

func Verify(root string) (Manifest, error) { return VerifyFor(root, runtime.GOOS, runtime.GOARCH) }

// VerifyFor validates a distribution for a specified platform without executing
// its contents. Runtime launch always uses Verify for the actual host platform.
func VerifyFor(root, goos, arch string) (Manifest, error) {
	var m Manifest
	b, e := securefile.Read(filepath.Join(root, "manifest.json"), 1<<20, false)
	if e != nil {
		return m, errors.New("runtime manifest missing")
	}
	if json.Unmarshal(b, &m) != nil || m.Version != 1 || m.OS != goos || m.Arch != arch {
		return m, errors.New("runtime platform or manifest mismatch")
	}
	seen := map[string]bool{}
	for _, entry := range m.Files {
		if !fs.ValidPath(entry.Path) || strings.ContainsAny(entry.Path, "\\:") || path.Clean(entry.Path) != entry.Path || seen[entry.Path] {
			return m, errors.New("unsafe or repeated runtime path")
		}
		seen[entry.Path] = true
		p := filepath.Join(root, entry.Path)
		i, e := os.Lstat(p)
		if e != nil || !i.Mode().IsRegular() {
			return m, errors.New("runtime component is missing or not regular")
		}
		f, e := os.Open(p)
		if e != nil {
			return m, e
		}
		h := sha256.New()
		_, e = io.Copy(h, f)
		f.Close()
		if e != nil || hex.EncodeToString(h.Sum(nil)) != entry.SHA256 {
			return m, errors.New("runtime checksum mismatch")
		}
	}
	for _, name := range required(goos) {
		if !seen[name] {
			return m, errors.New("runtime clients are missing")
		}
	}
	if goos != "darwin" && goos != "windows" {
		return m, errors.New("unsupported runtime platform")
	}
	return m, nil
}

func Copy(source, destination string) error {
	m, e := Verify(source)
	if e != nil {
		return e
	}
	if e = securefile.Dir(destination); e != nil {
		return e
	}
	for _, entry := range m.Files {
		p := filepath.Join(destination, entry.Path)
		if e = securefile.Dir(filepath.Dir(p)); e != nil {
			return e
		}
		in, e := os.Open(filepath.Join(source, entry.Path))
		if e != nil {
			return e
		}
		out, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
		if e != nil {
			in.Close()
			return e
		}
		_, e = io.Copy(out, in)
		in.Close()
		ce := out.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
		if e = sealCopy(p); e != nil {
			return e
		}
	}
	if e = securefile.Write(filepath.Join(destination, "manifest.json"), m); e != nil {
		return e
	}
	_, e = Verify(destination)
	return e
}

func required(goos string) []string {
	if goos == "windows" {
		return []string{"bin/mihomo.exe", "bin/openconnect.exe", "bin/wintun.dll", "certs/ca-bundle.crt"}
	}
	return []string{"bin/mihomo", "bin/openconnect"}
}
