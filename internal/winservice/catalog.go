package winservice

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"regexp"
	"strings"

	"netlaunch/internal/runtimebundle"
)

const ServiceName = "LuminaVPNService"
const PipeName = `\\.\pipe\LuminaVPN.Service.v1`
const StopPipeName = PipeName + ".stop"
const PipeClientRights uint32 = 0x00100003 // synchronize + read/write data; no create-instance bit 4.
const PipeFirstInstance uint32 = 0x00080000
const PipeRejectRemote uint32 = 0x00000008

var sidText = regexp.MustCompile(`^S-1-[0-9]+(?:-[0-9]+)+$`)
var releaseText = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
var digestText = regexp.MustCompile(`^[a-f0-9]{64}$`)
var engineRunID = regexp.MustCompile(`^netlaunch-[a-f0-9]{32}$`)

// PipeSDDL grants individual data rights to the permanent enrolled owner SID.
// This allows only connection/typed attachment eligibility: kernel tuple/run
// authorization remains in the broker. Generic-write/create-instance is denied.
func PipeSDDL(serviceSID, logonSID string) (string, error) {
	if !sidText.MatchString(serviceSID) || !sidText.MatchString(logonSID) {
		return "", errors.New("invalid pipe principal")
	}
	return "D:P(A;;GA;;;SY)(A;;GA;;;" + serviceSID + ")(A;;0x00100003;;;" + logonSID + ")", nil
}

type ExecutableKind string

const (
	ServiceImage    ExecutableKind = "service"
	UserWorkerImage ExecutableKind = "user_worker"
	CoreImage       ExecutableKind = "core"
	VPNImage        ExecutableKind = "vpn"
	LifecycleImage  ExecutableKind = "lifecycle"
)

var fixedImages = map[ExecutableKind]string{ServiceImage: "lumina-service.exe", UserWorkerImage: "lumina-user-worker.exe", LifecycleImage: "netlaunch.exe", CoreImage: "runtime/bin/mihomo.exe", VPNImage: "runtime/bin/openconnect.exe"}

type FilePin struct {
	SHA256 string `json:"sha256"`
}
type ReleaseCatalog struct {
	ReleaseID             string                     `json:"release_id"`
	Files                 map[ExecutableKind]FilePin `json:"files"`
	RuntimeManifestSHA256 string                     `json:"runtime_manifest_sha256"`
}
type TrustedFiles interface{ ReadProtected(string) ([]byte, error) }
type Installation struct {
	root            string
	release         string
	images          map[ExecutableKind]string
	pins            map[ExecutableKind]FilePin
	runtimeRoot     string
	runtimeManifest runtimebundle.Manifest
}

var fixedRuntimePaths = []string{
	"bin/iconv.dll", "bin/libgcc_s_seh-1.dll", "bin/libgmp-10.dll", "bin/libgnutls-30.dll", "bin/libhogweed-6.dll", "bin/libintl-8.dll", "bin/liblz4.dll", "bin/libnettle-8.dll", "bin/libopenconnect-5.dll", "bin/libstoken-1.dll", "bin/libtasn1-6.dll", "bin/libwinpthread-1.dll", "bin/libxml2-2.dll", "bin/mihomo.exe", "bin/openconnect.exe", "bin/wintun.dll", "bin/zlib1.dll", "certs/ca-bundle.crt",
}

// ValidateInstallation accepts only the admin-owned machine install root that
// the host derives independently. A profile/runtime/manifest supplied by RPC
// cannot authorize execution. TrustedFiles also rejects reparse points and
// writable-by-user owners/DACLs before returning the same verified bytes.
func ValidateInstallation(machineRoot string, c ReleaseCatalog, fs TrustedFiles) (Installation, error) {
	if fs == nil || !filepath.IsAbs(machineRoot) || filepath.Clean(machineRoot) != machineRoot || !releaseText.MatchString(c.ReleaseID) || len(c.Files) != len(fixedImages) || !digestText.MatchString(c.RuntimeManifestSHA256) {
		return Installation{}, errors.New("invalid machine release catalog")
	}
	installation := Installation{root: machineRoot, release: c.ReleaseID, images: map[ExecutableKind]string{}, pins: map[ExecutableKind]FilePin{}}
	for kind, relative := range fixedImages {
		pin, ok := c.Files[kind]
		if !ok || !digestText.MatchString(pin.SHA256) {
			return Installation{}, errors.New("missing fixed executable pin")
		}
		path := filepath.Join(machineRoot, "releases", c.ReleaseID, filepath.FromSlash(relative))
		data, err := fs.ReadProtected(path)
		if err != nil {
			return Installation{}, err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != pin.SHA256 {
			return Installation{}, errors.New("installed executable differs from protected release pin")
		}
		installation.images[kind] = path
		installation.pins[kind] = pin
	}
	runtimeRoot := filepath.Join(machineRoot, "releases", c.ReleaseID, "runtime")
	data, err := fs.ReadProtected(filepath.Join(runtimeRoot, "manifest.json"))
	if err != nil {
		return Installation{}, err
	}
	sum := sha256.Sum256(data)
	if len(data) > 1<<20 || hex.EncodeToString(sum[:]) != c.RuntimeManifestSHA256 {
		return Installation{}, errors.New("runtime manifest differs from protected release pin")
	}
	var manifest runtimebundle.Manifest
	if decodeState(data, &manifest) != nil || manifest.Version != 1 || manifest.OS != "windows" || manifest.Arch != "amd64" || len(manifest.Files) != len(fixedRuntimePaths) {
		return Installation{}, errors.New("runtime manifest is not the fixed complete Windows bundle")
	}
	allowed := map[string]bool{}
	for _, name := range fixedRuntimePaths {
		allowed[name] = true
	}
	seen := map[string]bool{}
	for _, file := range manifest.Files {
		if !allowed[file.Path] || seen[file.Path] || !digestText.MatchString(file.SHA256) {
			return Installation{}, errors.New("runtime manifest has missing, extra or repeated paths")
		}
		seen[file.Path] = true
		data, err = fs.ReadProtected(filepath.Join(runtimeRoot, filepath.FromSlash(file.Path)))
		if err != nil {
			return Installation{}, err
		}
		sum = sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != file.SHA256 {
			return Installation{}, errors.New("installed runtime file differs from protected bundle")
		}
		for kind, relative := range map[ExecutableKind]string{CoreImage: "bin/mihomo.exe", VPNImage: "bin/openconnect.exe"} {
			if file.Path == relative && c.Files[kind].SHA256 != file.SHA256 {
				return Installation{}, errors.New("runtime and executable release pins disagree")
			}
		}
	}
	installation.runtimeRoot = runtimeRoot
	installation.runtimeManifest = manifest
	return installation, nil
}
func (i Installation) Executable(kind ExecutableKind) (string, error) {
	path := i.images[kind]
	if path == "" || i.root == "" {
		return "", errors.New("trusted fixed executable unavailable")
	}
	return path, nil
}
func (i Installation) Ready() bool {
	return i.root != "" && len(i.images) == len(fixedImages) && i.runtimeRoot != "" && len(i.runtimeManifest.Files) == len(fixedRuntimePaths)
}
func (i Installation) RuntimeManifest() (string, runtimebundle.Manifest, error) {
	if !i.Ready() {
		return "", runtimebundle.Manifest{}, errors.New("trusted complete runtime unavailable")
	}
	manifest := i.runtimeManifest
	manifest.Files = append([]runtimebundle.File{}, manifest.Files...)
	return i.runtimeRoot, manifest, nil
}

type InstallPlan struct {
	Version             int            `json:"version"`
	Schema              string         `json:"schema"`
	ServiceName         string         `json:"service_name"`
	ImageKind           ExecutableKind `json:"image_kind"`
	ImageRelative       string         `json:"image_relative"`
	Account             string         `json:"account"`
	AutoConnect         bool           `json:"auto_connect"`
	RequiresReview      bool           `json:"requires_review"`
	Installed           bool           `json:"installed"`
	ServiceArguments    []string       `json:"service_arguments"`
	SupportedEntries    []string       `json:"supported_entries"`
	BootstrapAvailable  bool           `json:"bootstrap_available"`
	RecoveryServiceName string         `json:"recovery_service_name"`
	RecoveryArguments   []string       `json:"recovery_arguments"`
	TargetPreflight     string         `json:"target_preflight"`
	TargetRoot          string         `json:"target_root,omitempty"`
	DataRoot            string         `json:"data_root,omitempty"`
}

func PreparedInstallPlan() InstallPlan {
	return InstallPlan{Version: 1, Schema: "lumina-service-install-v1", ServiceName: ServiceName, ImageKind: ServiceImage, ImageRelative: "releases/<reviewed-release>/lumina-service.exe", Account: "LocalSystem with an explicit service SID", AutoConnect: false, RequiresReview: true, ServiceArguments: []string{"--service"}, SupportedEntries: []string{"--service", "--bootstrap", "--recover-service", "--recover", "--uninstall", "--print-install-plan"}, BootstrapAvailable: true, RecoveryServiceName: RecoveryServiceName, RecoveryArguments: []string{"--recover-service"}, TargetPreflight: "unknown"}
}
func ValidProfileID(id string) bool {
	return releaseText.MatchString(id) && !strings.Contains(id, "..")
}
