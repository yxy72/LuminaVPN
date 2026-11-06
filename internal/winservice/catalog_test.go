package winservice

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"netlaunch/internal/runtimebundle"
)

type catalogFixtureFiles map[string][]byte

func (f catalogFixtureFiles) ReadProtected(path string) ([]byte, error) {
	data, ok := f[path]
	if !ok {
		return nil, errors.New("unlisted catalog fixture path")
	}
	return append([]byte{}, data...), nil
}
func fixtureSHA(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func fixtureCatalog(t *testing.T) (string, ReleaseCatalog, catalogFixtureFiles, runtimebundle.Manifest) {
	t.Helper()
	root, err := filepath.Abs("catalog-fixture")
	if err != nil {
		t.Fatal(err)
	}
	files := catalogFixtureFiles{}
	catalog := ReleaseCatalog{ReleaseID: "release-1", Files: map[ExecutableKind]FilePin{}}
	manifest := runtimebundle.Manifest{Version: 1, OS: "windows", Arch: "amd64", Mihomo: "fixture", OpenConnect: "fixture"}
	for _, name := range fixedRuntimePaths {
		data := []byte("fixture:" + name)
		files[filepath.Join(root, "releases", "release-1", "runtime", filepath.FromSlash(name))] = data
		manifest.Files = append(manifest.Files, runtimebundle.File{Path: name, SHA256: fixtureSHA(data)})
	}
	for kind, relative := range fixedImages {
		path := filepath.Join(root, "releases", "release-1", filepath.FromSlash(relative))
		data := files[path]
		if data == nil {
			data = []byte("fixture:" + relative)
			files[path] = data
		}
		catalog.Files[kind] = FilePin{SHA256: fixtureSHA(data)}
	}
	writeFixtureManifest(t, root, &catalog, files, manifest)
	return root, catalog, files, manifest
}
func writeFixtureManifest(t *testing.T, root string, catalog *ReleaseCatalog, files catalogFixtureFiles, manifest runtimebundle.Manifest) {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	files[filepath.Join(root, "releases", "release-1", "runtime", "manifest.json")] = data
	catalog.RuntimeManifestSHA256 = fixtureSHA(data)
}

func TestInstallationPinsCompleteFixedRuntimeAndReturnsAnIndependentCopy(t *testing.T) {
	root, catalog, files, _ := fixtureCatalog(t)
	installation, err := ValidateInstallation(root, catalog, files)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot, manifest, err := installation.RuntimeManifest()
	if err != nil || len(manifest.Files) != 18 || runtimeRoot != filepath.Join(root, "releases", "release-1", "runtime") {
		t.Fatal("complete fixed runtime not available")
	}
	manifest.Files[0].Path = "foreign.exe"
	_, again, _ := installation.RuntimeManifest()
	if again.Files[0].Path == "foreign.exe" {
		t.Fatal("caller mutated installed trust catalog")
	}
	if _, err = installation.Executable(ExecutableKind("shell")); err == nil {
		t.Fatal("arbitrary executable kind accepted")
	}
}

func TestInstalledRuntimeRejectsExtraMissingRepeatedPathsAndChangedBytes(t *testing.T) {
	for _, kind := range []string{"extra", "missing", "repeated", "bytes", "manifest_pin", "executable_pin", "release_path"} {
		t.Run(kind, func(t *testing.T) {
			root, catalog, files, manifest := fixtureCatalog(t)
			switch kind {
			case "extra":
				manifest.Files[0].Path = "bin/arbitrary.exe"
				writeFixtureManifest(t, root, &catalog, files, manifest)
			case "missing":
				manifest.Files = manifest.Files[:17]
				writeFixtureManifest(t, root, &catalog, files, manifest)
			case "repeated":
				manifest.Files[1] = manifest.Files[0]
				writeFixtureManifest(t, root, &catalog, files, manifest)
			case "bytes":
				files[filepath.Join(root, "releases", "release-1", "runtime", "bin", "wintun.dll")] = []byte("changed")
			case "manifest_pin":
				catalog.RuntimeManifestSHA256 = strings.Repeat("0", 64)
			case "executable_pin":
				catalog.Files[CoreImage] = FilePin{SHA256: strings.Repeat("0", 64)}
			case "release_path":
				catalog.ReleaseID = "../user"
			}
			if _, err := ValidateInstallation(root, catalog, files); err == nil {
				t.Fatal("runtime trust boundary accepted invalid release")
			}
		})
	}
}
