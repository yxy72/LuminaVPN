//go:build windows

package engine

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"netlaunch/internal/auth"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/runtimebundle"
	"netlaunch/internal/securefile"
)

func requireServiceSystem() error {
	if !platform.WindowsClientBuild {
		return errors.New("installed Windows client helper required")
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || u.User.Sid == nil || u.User.Sid.String() != "S-1-5-18" {
		return errors.New("LocalSystem executor required")
	}
	return securefile.RequireAdmin()
}
func serviceDataRoot() (string, error) {
	p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", err
	}
	return filepath.Join(p, "LuminaVPN", "ServiceState"), nil
}
func ServiceRunPath(r ServiceRunReference) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	root, err := serviceDataRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "runs", r.ProfileID, r.RunID), nil
}
func serviceHash(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// PrepareServiceRun creates only a new SYSTEM-owned run under the fixed machine
// state root. Trusted runtime bytes are supplied by the protected-installation
// adapter, never by the data-only user request.
func PrepareServiceRun(in ServicePrepareInput, rt ServiceRuntime) (ServicePrepared, error) {
	if err := requireServiceSystem(); err != nil {
		return ServicePrepared{}, err
	}
	now := time.Now()
	if err := in.Binding.Validate(in.Mode, now); err != nil {
		return ServicePrepared{}, err
	}
	if in.Binding.NodesSHA256 != "" || in.Binding.RuntimeSHA256 != "" || in.Binding.LifecycleSHA256 != "" {
		return ServicePrepared{}, errors.New("caller cannot assign service input digests")
	}
	if err := in.Config.ValidateForIntent(in.Channels); err != nil {
		return ServicePrepared{}, err
	}
	nodes := in.Nodes
	var err error
	if len(nodes) > 0 || in.Channels.Personal {
		nodes, err = policy.SanitizeNodes(nodes)
		if err != nil {
			return ServicePrepared{}, err
		}
	}
	if err = policy.ValidateEndpointsForIntent(in.Config, nodes, in.Channels); err != nil {
		return ServicePrepared{}, err
	}
	if rt.Manifest.Version != 1 || rt.Manifest.OS != "windows" || rt.Manifest.Arch != "amd64" || len(rt.Manifest.Files) != 18 || len(rt.Files) != 18 {
		return ServicePrepared{}, errors.New("fixed Windows runtime requires all eighteen protected files")
	}
	if len(rt.Lifecycle) == 0 || len(rt.Lifecycle) > 128<<20 {
		return ServicePrepared{}, errors.New("protected lifecycle image bytes required")
	}
	for _, entry := range rt.Manifest.Files {
		b, ok := rt.Files[entry.Path]
		sum := sha256.Sum256(b)
		if !ok || len(b) == 0 || hex.EncodeToString(sum[:]) != entry.SHA256 {
			return ServicePrepared{}, errors.New("protected runtime bytes differ from release pin")
		}
	}
	root, err := serviceDataRoot()
	if err != nil {
		return ServicePrepared{}, err
	}
	if err = securefile.CheckDir(root); err != nil {
		return ServicePrepared{}, err
	}
	runs := filepath.Join(root, "runs")
	if err = securefile.CheckDir(runs); err != nil {
		return ServicePrepared{}, err
	}
	profile := filepath.Join(runs, in.Binding.ProfileID)
	if err = securefile.Dir(profile); err != nil {
		return ServicePrepared{}, err
	}
	unlock, err := securefile.Lock(filepath.Join(profile, "prepare.lock"), 10*time.Second)
	if err != nil {
		return ServicePrepared{}, err
	}
	defer unlock()
	ref := preparationReference(in.Binding)
	if err = servicePreparationNotAborted(profile, ref); err != nil {
		return ServicePrepared{}, err
	}
	helperSum := sha256.Sum256(rt.Lifecycle)
	in.Binding.LifecycleSHA256 = hex.EncodeToString(helperSum[:])
	b := make([]byte, 16)
	if _, err = rand.Read(b); err != nil {
		return ServicePrepared{}, err
	}
	id := "netlaunch-" + hex.EncodeToString(b)
	run := filepath.Join(profile, id)
	if _, err = os.Lstat(run); !errors.Is(err, os.ErrNotExist) {
		return ServicePrepared{}, errors.New("fresh service run already exists")
	}
	if err = securefile.Dir(run); err != nil {
		return ServicePrepared{}, err
	}
	claim := servicePreparationClaim{Version: 1, ServicePreparationReference: ref, RunID: id, ExecutorSID: "S-1-5-18", LifecycleSHA256: in.Binding.LifecycleSHA256}
	if err = securefile.Write(filepath.Join(run, "preparation.json"), claim); err != nil {
		return ServicePrepared{}, err
	}
	physical, err := platform.Discover()
	if err != nil {
		return ServicePrepared{}, err
	}
	vpn, tun, err := platform.Candidates()
	if err != nil {
		return ServicePrepared{}, err
	}
	port, err := platform.FreePort()
	if err != nil {
		return ServicePrepared{}, err
	}
	in.Binding.NodesSHA256, in.Binding.RuntimeSHA256 = serviceHash(nodes), serviceHash(rt.Manifest)
	intent := in.Channels
	m := Manifest{Version: 1, OwnerSID: "S-1-5-18", Service: &in.Binding, Mode: in.Mode, Channels: &intent, Config: in.Config, Binding: policy.Binding{Physical: physical.Interface, VPN: vpn, TUN: tun, ControllerPort: port}, Network: physical, Executable: frozenSelf(run), Created: now}
	if m.Mode == Validation {
		m.ValidationTimeout = in.Binding.Deadline.Sub(now)
	}
	if err = m.ValidateMode(); err != nil {
		return ServicePrepared{}, err
	}
	if err = securefile.Write(filepath.Join(run, "manifest.json"), m); err != nil {
		return ServicePrepared{}, err
	}
	if err = securefile.Write(filepath.Join(run, "nodes.json"), nodes); err != nil {
		return ServicePrepared{}, err
	}
	if err = securefile.Bytes(filepath.Join(run, "netlaunch.exe"), rt.Lifecycle); err != nil {
		return ServicePrepared{}, err
	}
	for _, entry := range rt.Manifest.Files {
		path := filepath.Join(run, "runtime", filepath.FromSlash(entry.Path))
		if err = securefile.Dir(filepath.Dir(path)); err != nil {
			return ServicePrepared{}, err
		}
		if err = securefile.Bytes(path, rt.Files[entry.Path]); err != nil {
			return ServicePrepared{}, err
		}
	}
	if err = securefile.Write(filepath.Join(run, "runtime", "manifest.json"), rt.Manifest); err != nil {
		return ServicePrepared{}, err
	}
	if _, err = runtimebundle.Verify(filepath.Join(run, "runtime")); err != nil {
		return ServicePrepared{}, err
	}
	pending := in.Channels.Company
	if in.Channels.Company && in.Auth != nil && in.Auth.ValidAt(now) {
		v, e := auth.EncodeRuntime(in.Config.VPN, *in.Auth)
		if e != nil {
			return ServicePrepared{}, e
		}
		if err = securefile.Write(filepath.Join(run, "auth.json"), v); err != nil {
			return ServicePrepared{}, err
		}
		pending = false
	}
	return ServicePrepared{RunID: id, SpecDigest: runSpecDigest(immutableRunSpec(m)), Mode: m.Mode, Deadline: in.Binding.Deadline, CompanyPending: pending}, nil
}

func ServiceManifest(r ServiceRunReference) (string, Manifest, error) {
	if err := requireServiceSystem(); err != nil {
		return "", Manifest{}, err
	}
	run, err := ServiceRunPath(r)
	if err != nil {
		return "", Manifest{}, err
	}
	m, err := ReadManifest(run)
	if err != nil {
		return "", m, err
	}
	if m.Service == nil || m.Service.ProfileID != r.ProfileID || m.Service.RunRef != r.BindingRunRef || m.Service.ServiceInstance != r.ServiceInstance || runSpecDigest(immutableRunSpec(m)) != r.SpecDigest {
		return "", m, errors.New("frozen service run reference mismatch")
	}
	if _, readErr := readRunFile(run, "state.json", 4<<20); readErr == nil {
		state, stateErr := load(run)
		if stateErr != nil || state.Manifest.Service == nil || state.RunSpecDigest != r.SpecDigest {
			return "", m, errors.New("private service run specification differs from bound reference")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", m, readErr
	}
	return run, m, nil
}
func ServeServiceRun(r ServiceRunReference) error {
	run, m, err := ServiceManifest(r)
	if err != nil {
		return err
	}
	if err = servicePreparationNotAborted(filepath.Dir(run), preparationReference(*m.Service)); err != nil {
		return err
	}
	var nodes []policy.Node
	if err = readJSON(filepath.Join(run, "nodes.json"), &nodes); err != nil {
		return err
	}
	rt, err := runtimebundle.Verify(filepath.Join(run, "runtime"))
	if err != nil {
		return err
	}
	if serviceHash(nodes) != m.Service.NodesSHA256 || serviceHash(rt) != m.Service.RuntimeSHA256 {
		return errors.New("prepared service data changed")
	}
	return Internal("serve", run)
}
