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
	"time"

	"golang.org/x/sys/windows"
	"netlaunch/internal/auth"
	"netlaunch/internal/policy"
	p "netlaunch/internal/serviceprotocol"
)

// ServiceUserSnapshotData is private bootstrap data for the installed service.
// It must never be used as a renderer DTO, journal or diagnostic snapshot.
type ServiceUserSnapshotData struct {
	Policy          policy.Config `json:"policy"`
	SavedPolicy     policy.Config `json:"saved_policy"`
	Nodes           []policy.Node `json:"nodes"`
	Session         *auth.Session `json:"session,omitempty"`
	PolicyRevision  string        `json:"policy_revision"`
	EffectiveDigest string        `json:"effective_digest"`
}
type serviceSnapshotRequest struct {
	ProfileID string `json:"profile_id"`
}
type serviceSnapshotDependencies struct {
	identity  func() error
	profile   func() (string, error)
	policy    func(string) (policy.Config, error)
	effective func(string, policy.Config) (policy.Config, []policy.Node, error)
	session   func(string, policy.VPN) (auth.Session, bool)
	now       func() time.Time
}

func serviceInteractiveUser() error {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user.User.Sid == nil || user.User.Sid.String() == "S-1-5-18" {
		return errors.New("real interactive user process required")
	}
	var session uint32
	if windows.ProcessIdToSessionId(uint32(os.Getpid()), &session) != nil || session == 0 {
		return errors.New("interactive user session required")
	}
	return nil
}
func serviceDefaultProfile(requested string, resolve func() (string, error)) (string, error) {
	profile, err := resolve()
	if err != nil {
		return "", errors.New("default user profile unavailable")
	}
	profile, err = filepath.Abs(profile)
	if err != nil {
		return "", errors.New("default user profile unavailable")
	}
	profile = filepath.Clean(profile)
	sum := sha256.Sum256([]byte(strings.ToLower(profile)))
	if requested != hex.EncodeToString(sum[:16]) {
		return "", errors.New("profile is not enrolled in the user worker")
	}
	return profile, nil
}
func readServiceUserFrame(in io.Reader, value any) error {
	raw, err := io.ReadAll(io.LimitReader(in, 4097))
	if err != nil || len(raw) > 4096 {
		return errors.New("invalid private worker frame")
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return errors.New("invalid private worker request")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing private worker data")
	}
	return nil
}
func writeServicePrivateFrame(out io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > p.MaxFrame {
		return errors.New("private worker result unavailable")
	}
	defer clear(encoded)
	frame := append(encoded, '\n')
	defer clear(frame)
	if n, err := out.Write(frame); err != nil || n != len(frame) {
		return errors.New("private worker output disconnected")
	}
	return nil
}

// ServiceUserSnapshot is invoked only through the installed FixedExecutor's
// --snapshot-worker entry and anonymous pipes, under a duplicated real primary
// user token. SYSTEM/thread impersonation is rejected before any profile read.
func ServiceUserSnapshot(in io.Reader, out io.Writer) error {
	return serviceUserSnapshot(in, out, serviceSnapshotDependencies{serviceInteractiveUser, DefaultProfile, DesktopWorkspacePolicy, DesktopWorkspaceProfile, auth.Load, time.Now})
}
func serviceUserSnapshot(in io.Reader, out io.Writer, deps serviceSnapshotDependencies) error {
	if err := deps.identity(); err != nil {
		return errors.New("interactive user identity unavailable")
	}
	var request serviceSnapshotRequest
	if readServiceUserFrame(in, &request) != nil || !p.ValidID(request.ProfileID) {
		return errors.New("invalid user snapshot request")
	}
	profile, err := serviceDefaultProfile(request.ProfileID, deps.profile)
	if err != nil {
		return err
	}
	base, err := deps.policy(profile)
	if err != nil {
		return errors.New("saved user policy unavailable")
	}
	effective, nodes, err := deps.effective(profile, base)
	if err != nil {
		return errors.New("validated user inventory unavailable")
	}
	// An atomic policy replacement during this read cannot silently change the
	// snapshot's compare-and-swap identity.
	again, err := deps.policy(profile)
	if err != nil || policyRevision(base) != policyRevision(again) {
		return errors.New("saved policy changed during snapshot")
	}
	digestBytes, err := json.Marshal(struct {
		Policy policy.Config
		Nodes  []policy.Node
	}{effective, nodes})
	if err != nil {
		return errors.New("private configuration identity unavailable")
	}
	sum := sha256.Sum256(digestBytes)
	clear(digestBytes)
	data := ServiceUserSnapshotData{Policy: effective, SavedPolicy: base, Nodes: nodes, PolicyRevision: policyRevision(base), EffectiveDigest: hex.EncodeToString(sum[:])}
	session, valid := deps.session(profile, base.VPN)
	if valid && session.Validate(base.VPN) == nil && session.ValidAt(deps.now()) {
		data.Session = &session
	}
	defer func() { session.Cookie = ""; data.Session = nil }()
	return writeServicePrivateFrame(out, data)
}
