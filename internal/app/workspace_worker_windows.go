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
	if err := serviceInteractiveUser(); err != nil {
		return errors.New("workspace worker requires a verified interactive user process")
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
	image, err := os.Executable()
	if err != nil {
		return errors.New("workspace runtime unavailable")
	}
	d := DesktopCommands{Profile: profile, Runtime: filepath.Join(filepath.Dir(image), "runtime")}
	ctx := context.Background() // The service owns the process/operation lifetime.
	result, err := d.Execute(ctx, request.Workspace)
	response := map[string]any{"completed": true, "result": result}
	if err != nil {
		var feedback *p.Error
		if !errors.As(err, &feedback) || !p.WorkspaceFeedbackCode(feedback.Code) {
			return errors.New("workspace action failed; private details omitted")
		}
		response = map[string]any{"completed": false, "error_code": feedback.Code}
	}
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded) > p.MaxFrame {
		return errors.New("workspace result unavailable")
	}
	_, err = out.Write(append(encoded, '\n'))
	return err
}
