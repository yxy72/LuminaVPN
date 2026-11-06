//go:build windows

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	p "netlaunch/internal/serviceprotocol"
)

type workspaceWorkerRequest struct {
	ProfileID string             `json:"profile_id"`
	Workspace p.WorkspacePayload `json:"workspace"`
}

// WorkspaceWorker runs only in the real interactive user process created with
// the verified caller token. No filesystem path, executable or argv is accepted
// on its input. A privileged host may not substitute thread impersonation here.
func WorkspaceWorker(in io.Reader, out io.Writer) error {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || u.User.Sid == nil || u.User.Sid.String() == "S-1-5-18" {
		return errors.New("workspace worker requires the interactive user process")
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(uint32(os.Getpid()), &session); err != nil || session == 0 {
		return errors.New("workspace worker requires an interactive logon session")
	}
	raw, err := io.ReadAll(io.LimitReader(in, p.MaxFrame+1))
	if err != nil || len(raw) > p.MaxFrame {
		return errors.New("invalid workspace frame")
	}
	var request workspaceWorkerRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil {
		return errors.New("invalid workspace request")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return errors.New("unexpected workspace trailing data")
	}
	if err := request.Workspace.Validate(); err != nil {
		return errors.New("invalid workspace action")
	}
	profile, err := DefaultProfile()
	if err != nil {
		return errors.New("user profile unavailable")
	}
	profile, err = filepath.Abs(profile)
	if err != nil {
		return errors.New("user profile unavailable")
	}
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(profile))))
	if request.ProfileID != hex.EncodeToString(sum[:16]) {
		return errors.New("profile is not enrolled in the user workspace")
	}
	d := DesktopCommands{Profile: profile}
	w := request.Workspace
	ctx := context.Background() // The service owns the process/operation lifetime.
	var result any
	switch w.Action {
	case "initialize":
		result, err = d.Initialize(ctx, w.PolicyJSON, w.BootstrapJSON)
	case "apply":
		result, err = d.ApplyDraft(ctx, w.PolicyJSON, w.ExpectedPolicyRevision)
	case "rollback":
		result, err = d.Rollback(ctx, w.Revision, w.ExpectedPolicyRevision)
	case "import_nodes":
		result, err = d.ImportNodes(ctx, []byte(w.Content))
	case "sync":
		result, err = d.SyncSubscriptions(ctx)
	case "sources_save":
		result, err = d.SaveSources(ctx, w.SourcesJSON, w.ExpectedPolicyRevision)
	case "cleanup":
		result, err = d.ApplyCleanup(ctx, w.OpaqueRunID)
	default:
		return errors.New("workspace action unavailable")
	}
	if err != nil {
		return errors.New("workspace action failed; private details omitted")
	}
	encoded, err := json.Marshal(map[string]any{"completed": true, "result": result})
	if err != nil || len(encoded) > p.MaxFrame {
		return errors.New("workspace result unavailable")
	}
	_, err = out.Write(append(encoded, '\n'))
	return err
}
