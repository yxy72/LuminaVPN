//go:build windows

package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"netlaunch/internal/auth"
	"netlaunch/internal/engine"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	p "netlaunch/internal/serviceprotocol"
	"netlaunch/internal/winservice"
)

type ServicePreparePayload struct {
	ServiceOwnerPID   int                  `json:"service_owner_pid"`
	ServiceOwnerBirth string               `json:"service_owner_birth"`
	Binding           winservice.Binding   `json:"binding"`
	Config            policy.Config        `json:"config"`
	Nodes             []policy.Node        `json:"nodes"`
	Mode              engine.RunMode       `json:"mode"`
	Channels          policy.ChannelIntent `json:"channels"`
	Auth              *auth.Session        `json:"auth,omitempty"`
}
type ServiceRunPayload struct {
	engine.ServiceRunReference
	Channels *policy.ChannelIntent `json:"channels,omitempty"`
	Auth     *auth.Session         `json:"auth,omitempty"`
}

func verifyServiceHostOwner(installation winservice.Installation, pid int, birth string) (platform.Identity, string, error) {
	if pid < 2 || uint64(pid) > uint64(^uint32(0)) || birth == "" {
		return platform.Identity{}, "", errors.New("live service owner identity required")
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return platform.Identity{}, "", err
	}
	defer windows.CloseHandle(h)
	actual, err := platform.ProcessIdentityFromHandle(h, pid)
	if err != nil {
		return actual, "", err
	}
	image, err := installation.Executable(winservice.ServiceImage)
	if err != nil {
		return actual, "", err
	}
	if actual.PID != pid || actual.Birth != birth || actual.OwnerSID != "S-1-5-18" || !strings.EqualFold(filepath.Clean(actual.Executable), filepath.Clean(image)) {
		return actual, "", errors.New("service owner differs from fixed installed identity")
	}
	var token windows.Token
	if err = windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return actual, "", err
	}
	defer token.Close()
	groups, err := token.GetTokenGroups()
	if err != nil {
		return actual, "", err
	}
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+winservice.ServiceName)
	if err != nil {
		return actual, "", err
	}
	member := false
	for _, g := range groups.AllGroups() {
		member = member || g.Sid.Equals(sid) && serviceHelperSIDEnabled(g.Attributes)
	}
	if !member {
		return actual, "", errors.New("service owner lacks the installed service SID")
	}
	b, err := installation.ReadProtectedExecutable(winservice.ServiceImage)
	if err != nil {
		return actual, "", err
	}
	sum := sha256.Sum256(b)
	return actual, hex.EncodeToString(sum[:]), nil
}

type serviceHelperEnvelope struct {
	Action  winservice.LifecycleAction `json:"action"`
	Payload json.RawMessage            `json:"payload"`
}

func decodeServiceHelperJSON(raw []byte, value any) error {
	if len(raw) == 0 || len(raw) > p.MaxFrame {
		return errors.New("bounded service helper data required")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return errors.New("invalid typed service helper data")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("multiple service helper values rejected")
	}
	return nil
}
func verifyServiceHelperInstallation() (winservice.Installation, error) {
	if !platform.WindowsClientBuild {
		return winservice.Installation{}, errors.New("installed Windows client helper required")
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || u.User.Sid == nil || u.User.Sid.String() != "S-1-5-18" {
		return winservice.Installation{}, errors.New("LocalSystem service helper required")
	}
	installation, err := winservice.LoadInstallation()
	if err != nil {
		return installation, err
	}
	image, err := installation.Executable(winservice.LifecycleImage)
	if err != nil {
		return installation, err
	}
	self, err := os.Executable()
	if err != nil || !strings.EqualFold(filepath.Clean(self), filepath.Clean(image)) {
		return installation, errors.New("service helper image differs from protected release")
	}
	return installation, nil
}

func serviceHelperSIDEnabled(attributes uint32) bool {
	return attributes&windows.SE_GROUP_ENABLED != 0 && attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0
}

var errMainServiceHelperSIDAbsent = errors.New("main service SID absent")

func verifyMainServiceHelperToken() error {
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+winservice.ServiceName)
	if err != nil {
		return err
	}
	groups, err := windows.GetCurrentProcessToken().GetTokenGroups()
	if err != nil {
		return err
	}
	for _, group := range groups.AllGroups() {
		if group.Sid.Equals(sid) {
			if serviceHelperSIDEnabled(group.Attributes) {
				return nil
			}
			return errors.New("main service SID disabled or deny-only")
		}
	}
	return errMainServiceHelperSIDAbsent
}

func serviceHelperRecoveryAction(action winservice.LifecycleAction) bool {
	return action == winservice.RecoverLifecycle || action == winservice.StatusLifecycle || action == winservice.AbortPrepareLifecycle
}

func serviceHelperRecoveryExitGate(action winservice.LifecycleAction, requireMain func() error, checkExit func() error) error {
	if action != winservice.RecoverLifecycle && action != winservice.AbortPrepareLifecycle {
		return nil
	}
	if err := requireMain(); err == nil {
		return nil // The live main broker has already joined its active work.
	} else if !errors.Is(err, errMainServiceHelperSIDAbsent) {
		return err
	}
	if checkExit == nil {
		return errors.New("original service owner exit proof unavailable")
	}
	return checkExit()
}

func serviceHelperRecoveryQuiescence(checkStopped, checkExit func() error) error {
	if checkStopped == nil || checkExit == nil {
		return errors.New("independent recovery quiescence proof unavailable")
	}
	if err := checkStopped(); err != nil {
		return err
	}
	return checkExit()
}

func verifyRecoveryPreparationHost(installation winservice.Installation, reference engine.ServicePreparationReference) error {
	bound, err := winservice.LoadRecoveryUnpreparedBinding(reference.ProfileID)
	if err != nil {
		return err
	}
	if bound.RunRef != reference.BindingRunRef || bound.ServiceInstance != reference.ServiceInstance || bound.PreparedRunID != "" || bound.SpecDigest != "" || bound.ExecutorSID != "S-1-5-18" {
		return errors.New("unprepared service owner binding changed")
	}
	image, err := installation.Executable(winservice.ServiceImage)
	if err != nil {
		return err
	}
	data, err := installation.ReadProtectedExecutable(winservice.ServiceImage)
	if err != nil {
		return err
	}
	defer clear(data)
	sum := sha256.Sum256(data)
	if bound.ServiceHostSHA256 != hex.EncodeToString(sum[:]) {
		return errors.New("unprepared service owner differs from protected release")
	}
	return engine.VerifyServiceHostExited(platform.Identity{PID: bound.ServiceHostPID, Birth: bound.ServiceHostBirth, Executable: image, OwnerSID: "S-1-5-18"}, bound.ServiceHostSHA256)
}

func authorizeServiceHelperAction(action winservice.LifecycleAction, requireMain func() error) error {
	switch action {
	case winservice.PrepareLifecycle, winservice.ServeLifecycle, winservice.SetChannelsLifecycle:
		return requireMain()
	case winservice.RecoverLifecycle, winservice.StatusLifecycle, winservice.AbortPrepareLifecycle:
		return nil // Each loader separately verifies its executor SID and durable binding.
	default:
		return errors.New("unsupported typed service lifecycle action")
	}
}
func prepareServiceBinding(in ServicePreparePayload) (engine.ServicePrepareInput, error) {
	b := in.Binding
	if b.PreparedRunID != "" || b.SpecDigest != "" || b.ExecutorSID != "S-1-5-18" || b.Mode != string(in.Mode) {
		return engine.ServicePrepareInput{}, errors.New("fresh service-issued run binding required")
	}
	return engine.ServicePrepareInput{Config: in.Config, Nodes: in.Nodes, Mode: in.Mode, Channels: in.Channels, Auth: in.Auth, Binding: engine.ServiceRunBinding{ProfileID: b.ProfileID, RunRef: b.RunRef, ServiceInstance: b.ServiceInstance, CallerSID: b.OwnerSID, LogonSID: b.LogonSID, AuthenticationID: b.AuthenticationID, SessionID: b.SessionID, ExecutorSID: b.ExecutorSID, Revision: b.Revision, Deadline: b.Deadline}}, nil
}
func verifyBoundServiceRun(r engine.ServiceRunReference, action winservice.LifecycleAction) error {
	return verifyBoundServiceRunWith(r, action, verifyMainServiceHelperToken, winservice.LoadPreparedBinding, winservice.LoadRecoveryBinding)
}

func verifyBoundServiceRunWith(r engine.ServiceRunReference, action winservice.LifecycleAction, mainRole func() error, main, recovery func(string) (winservice.Binding, error)) error {
	switch action {
	case winservice.ServeLifecycle, winservice.SetChannelsLifecycle, winservice.RecoverLifecycle, winservice.StatusLifecycle:
	default:
		return errors.New("unsupported bound service lifecycle action")
	}
	if err := r.Validate(); err != nil {
		return err
	}
	loader := main
	if err := mainRole(); err != nil {
		if !errors.Is(err, errMainServiceHelperSIDAbsent) || !serviceHelperRecoveryAction(action) {
			return err
		}
		loader = recovery
	}
	// A malformed main binding must never cause a switch of execution principal.
	// Both loaders independently reopen and validate the same protected enrollment.
	b, err := loader(r.ProfileID)
	if err != nil {
		return err
	}
	if b.ProfileID != r.ProfileID || b.PreparedRunID != r.RunID || b.SpecDigest != r.SpecDigest || b.RunRef != r.BindingRunRef || b.ServiceInstance != r.ServiceInstance || b.ExecutorSID != "S-1-5-18" {
		return errors.New("service-issued prepared run binding differs")
	}
	return nil
}

func verifyUnpreparedServiceRun(r engine.ServicePreparationReference) error {
	return verifyUnpreparedServiceRunWith(r, verifyMainServiceHelperToken, winservice.LoadUnpreparedBinding, winservice.LoadRecoveryUnpreparedBinding)
}

func verifyUnpreparedServiceRunWith(r engine.ServicePreparationReference, mainRole func() error, main, recovery func(string) (winservice.Binding, error)) error {
	if err := r.Validate(); err != nil {
		return err
	}
	loader := main
	if err := mainRole(); err != nil {
		if !errors.Is(err, errMainServiceHelperSIDAbsent) {
			return err
		}
		loader = recovery
	}
	b, err := loader(r.ProfileID)
	if err != nil {
		return err
	}
	if b.ProfileID != r.ProfileID || b.RunRef != r.BindingRunRef || b.ServiceInstance != r.ServiceInstance || b.ExecutorSID != "S-1-5-18" || b.PreparedRunID != "" || b.SpecDigest != "" {
		return errors.New("durably unprepared service binding differs")
	}
	return nil
}
func protectedServiceRuntime(installation winservice.Installation) (engine.ServiceRuntime, error) {
	root, manifest, err := installation.RuntimeManifest()
	if err != nil {
		return engine.ServiceRuntime{}, err
	}
	image, err := installation.Executable(winservice.LifecycleImage)
	if err != nil {
		return engine.ServiceRuntime{}, err
	}
	release := filepath.Dir(image)
	if !strings.EqualFold(filepath.Clean(root), filepath.Join(release, "runtime")) {
		return engine.ServiceRuntime{}, errors.New("runtime is outside protected release")
	}
	files := winservice.WindowsProtectedFiles{Root: release}
	rt := engine.ServiceRuntime{Manifest: manifest, Files: map[string][]byte{}}
	rt.Lifecycle, err = installation.ReadProtectedExecutable(winservice.LifecycleImage)
	if err != nil {
		return engine.ServiceRuntime{}, err
	}
	for _, entry := range manifest.Files {
		data, err := files.ReadProtected(filepath.Join(root, filepath.FromSlash(entry.Path)))
		if err != nil {
			return engine.ServiceRuntime{}, err
		}
		rt.Files[entry.Path] = data
	}
	return rt, nil
}

// ServiceHelper is a fixed stdin/stdout entry of the reviewed machine helper.
// No request can select an executable, shell, runtime or filesystem path.
func ServiceHelper(input io.Reader, output io.Writer) error {
	installation, err := verifyServiceHelperInstallation()
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(input, p.MaxFrame+1))
	if err != nil {
		return err
	}
	defer clear(raw)
	var envelope serviceHelperEnvelope
	if err = decodeServiceHelperJSON(raw, &envelope); err != nil {
		return err
	}
	defer clear(envelope.Payload)
	if err = authorizeServiceHelperAction(envelope.Action, verifyMainServiceHelperToken); err != nil {
		return err
	}
	var result any
	if envelope.Action == winservice.PrepareLifecycle {
		var payload ServicePreparePayload
		if err = decodeServiceHelperJSON(envelope.Payload, &payload); err != nil {
			return err
		}
		in, err := prepareServiceBinding(payload)
		if err != nil {
			return err
		}
		host, pin, err := verifyServiceHostOwner(installation, payload.ServiceOwnerPID, payload.ServiceOwnerBirth)
		if err != nil {
			return err
		}
		in.Binding.ServiceHost, in.Binding.ServiceHostSHA256 = host, pin
		rt, err := protectedServiceRuntime(installation)
		if err != nil {
			return err
		}
		result, err = engine.PrepareServiceRun(in, rt)
		if err != nil {
			return err
		}
	} else if envelope.Action == winservice.AbortPrepareLifecycle {
		var payload engine.ServicePreparationReference
		if err = decodeServiceHelperJSON(envelope.Payload, &payload); err != nil {
			return err
		}
		if err = verifyUnpreparedServiceRun(payload); err != nil {
			return err
		}
		if err = serviceHelperRecoveryExitGate(envelope.Action, verifyMainServiceHelperToken, func() error {
			return serviceHelperRecoveryQuiescence(winservice.RequireMainServiceStopped, func() error { return verifyRecoveryPreparationHost(installation, payload) })
		}); err != nil {
			return err
		}
		image, readErr := installation.ReadProtectedExecutable(winservice.LifecycleImage)
		if readErr != nil {
			return readErr
		}
		pin := sha256.Sum256(image)
		_, runtime, readErr := installation.RuntimeManifest()
		if readErr != nil {
			return readErr
		}
		verifyHistory := winservice.VerifyHistoricalServicePreparation
		if roleErr := verifyMainServiceHelperToken(); roleErr != nil {
			if !errors.Is(roleErr, errMainServiceHelperSIDAbsent) {
				return roleErr
			}
			verifyHistory = winservice.VerifyRecoveryHistoricalServicePreparation
		}
		proof, abortErr := engine.AbortServicePreparation(payload, hex.EncodeToString(pin[:]), runtime, func(reference engine.ServicePreparationReference, runID, lifecycleSHA, specDigest string) (bool, error) {
			return verifyHistory(reference.ProfileID, reference.BindingRunRef, reference.ServiceInstance, runID, lifecycleSHA, specDigest)
		})
		clean := abortErr == nil && proof.Clean
		code := ""
		if !clean {
			code = "PREPARATION_ABORT_INCOMPLETE"
		}
		result = struct {
			RunRef string                              `json:"run_ref"`
			Clean  bool                                `json:"clean"`
			Proof  engine.ServicePreparationAbortProof `json:"proof"`
			Error  string                              `json:"error,omitempty"`
		}{payload.BindingRunRef, clean, proof, code}
	} else {
		var payload ServiceRunPayload
		if err = decodeServiceHelperJSON(envelope.Payload, &payload); err != nil {
			return err
		}
		if err = verifyBoundServiceRun(payload.ServiceRunReference, envelope.Action); err != nil {
			return err
		}
		if err = serviceHelperRecoveryExitGate(envelope.Action, verifyMainServiceHelperToken, func() error {
			return serviceHelperRecoveryQuiescence(winservice.RequireMainServiceStopped, func() error { return engine.ServiceRecoveryHostExited(payload.ServiceRunReference) })
		}); err != nil {
			return err
		}
		if envelope.Action != winservice.SetChannelsLifecycle && (payload.Channels != nil || payload.Auth != nil) {
			return errors.New("unexpected service lifecycle fields")
		}
		switch envelope.Action {
		case winservice.ServeLifecycle:
			if err = engine.ServeServiceRun(payload.ServiceRunReference); err != nil {
				return err
			}
			result = map[string]any{"run_id": payload.RunID, "started": true}
		case winservice.RecoverLifecycle:
			proof, recoverErr := engine.RecoverServiceRun(payload.ServiceRunReference)
			clean := recoverErr == nil && proof.Clean
			code := ""
			if !clean {
				code = "RECOVERY_INCOMPLETE"
				proof.Clean = false
			}
			result = struct {
				RunID string                      `json:"run_id"`
				Clean bool                        `json:"clean"`
				Proof engine.ServiceRecoveryProof `json:"proof"`
				Error string                      `json:"error,omitempty"`
			}{payload.RunID, clean, proof, code}
		case winservice.StatusLifecycle:
			result, err = engine.ServiceStatus(payload.ServiceRunReference)
			if err != nil {
				return err
			}
		case winservice.SetChannelsLifecycle:
			if payload.Channels == nil {
				return errors.New("explicit desired channels required")
			}
			if payload.Auth != nil {
				if err = engine.RefreshServiceAuth(payload.ServiceRunReference, *payload.Auth); err != nil {
					return err
				}
			}
			if err = engine.SetServiceChannels(payload.ServiceRunReference, *payload.Channels); err != nil {
				return err
			}
			result, err = engine.ServiceStatus(payload.ServiceRunReference)
			if err != nil {
				return err
			}
		default:
			return errors.New("unsupported typed service lifecycle action")
		}
	}
	return json.NewEncoder(output).Encode(result)
}
