//go:build windows

package winservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	p "netlaunch/internal/serviceprotocol"
)

type LifecycleAction string

const (
	PrepareLifecycle      LifecycleAction = "prepare"
	ServeLifecycle        LifecycleAction = "serve"
	RecoverLifecycle      LifecycleAction = "recover"
	StatusLifecycle       LifecycleAction = "status"
	SetChannelsLifecycle  LifecycleAction = "set_channels"
	AbortPrepareLifecycle LifecycleAction = "abort_prepare"
)

type FixedExecutor struct{ installation Installation }

func NewFixedExecutor(installation Installation) (*FixedExecutor, error) {
	if !installation.Ready() {
		return nil, errors.New("trusted installation unavailable")
	}
	return &FixedExecutor{installation}, nil
}

type boundedBuffer struct{ bytes.Buffer }

func (b *boundedBuffer) Write(data []byte) (int, error) {
	if b.Len()+len(data) > p.MaxFrame {
		return 0, errors.New("fixed helper response limit")
	}
	return b.Buffer.Write(data)
}
func (e *FixedExecutor) verify(kind ExecutableKind) (string, error) {
	path, err := e.installation.Executable(kind)
	if err != nil {
		return "", err
	}
	_, err = e.installation.ReadProtectedExecutable(kind)
	if err != nil {
		return "", err
	}
	return path, nil
}
func (i Installation) ReadProtectedExecutable(kind ExecutableKind) ([]byte, error) {
	path, err := i.Executable(kind)
	if err != nil {
		return nil, err
	}
	data, err := (WindowsProtectedFiles{Root: i.root}).ReadProtected(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != i.pins[kind].SHA256 {
		return nil, errors.New("fixed image changed after release validation")
	}
	return data, nil
}
func (e *FixedExecutor) Lifecycle(ctx context.Context, action LifecycleAction, payload []byte) ([]byte, error) {
	if action != PrepareLifecycle && action != ServeLifecycle && action != RecoverLifecycle && action != StatusLifecycle && action != SetChannelsLifecycle && action != AbortPrepareLifecycle {
		return nil, errors.New("unsupported fixed lifecycle action")
	}
	if len(payload) > p.MaxFrame || !json.Valid(payload) {
		return nil, errors.New("invalid fixed lifecycle data")
	}
	path, err := e.verify(LifecycleImage)
	if err != nil {
		return nil, err
	}
	input, err := json.Marshal(struct {
		Action  LifecycleAction `json:"action"`
		Payload json.RawMessage `json:"payload"`
	}{action, payload})
	if err != nil {
		return nil, err
	}
	return runFixed(ctx, path, "_service-helper", input, 0)
}
func (e *FixedExecutor) UserWorkspace(ctx context.Context, principal VerifiedPrincipal, binding Binding, payload p.WorkspacePayload) ([]byte, error) {
	if payload.Validate() != nil {
		return nil, errors.New("invalid typed workspace worker input")
	}
	input, err := json.Marshal(struct {
		ProfileID string             `json:"profile_id"`
		Workspace p.WorkspacePayload `json:"workspace"`
	}{binding.ProfileID, payload})
	if err != nil {
		return nil, err
	}
	return e.userWorker(ctx, principal, binding, "--workspace-worker", input)
}

// UserSnapshot is a private fixed-image read under the real caller process
// token. Its potentially sensitive result remains anonymous-pipe data; it is
// not a public Snapshot RPC response or a durable operation payload.
func (e *FixedExecutor) UserSnapshot(ctx context.Context, principal VerifiedPrincipal, binding Binding) ([]byte, error) {
	input, err := json.Marshal(struct {
		ProfileID string `json:"profile_id"`
	}{binding.ProfileID})
	if err != nil {
		return nil, err
	}
	return e.userWorker(ctx, principal, binding, "--snapshot-worker", input)
}

func (e *FixedExecutor) userWorker(ctx context.Context, principal VerifiedPrincipal, binding Binding, entry string, input []byte) ([]byte, error) {
	if (entry != "--workspace-worker" && entry != "--snapshot-worker") || !principal.Verified() || principal.token == 0 || authorize(principal, binding, "S-1-5-18", binding.ServiceInstance) != nil || !p.ValidID(binding.ServiceInstance) || !ValidProfileID(binding.ProfileID) {
		return nil, errors.New("verified fixed user worker identity required")
	}
	path, err := e.verify(UserWorkerImage)
	if err != nil {
		return nil, err
	}
	var primary windows.Token
	if err = windows.DuplicateTokenEx(windows.Token(principal.token), windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_SESSIONID, nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
		return nil, err
	}
	defer primary.Close()
	return runFixed(ctx, path, entry, input, primary)
}
func runFixed(ctx context.Context, image, entry string, input []byte, userToken windows.Token) ([]byte, error) {
	if len(input) > p.MaxFrame {
		return nil, errors.New("fixed helper input limit")
	}
	command, err := fixedCommand(ctx, image, entry, userToken)
	if err != nil {
		return nil, err
	}
	command.Stdin = bytes.NewReader(input)
	command.Stderr = io.Discard
	output := &boundedBuffer{}
	command.Stdout = output
	if userToken != 0 {
		// Workers consume their fixed typed input only after assignment to a
		// service-owned kill-on-close job. Lifecycle/recovery helpers never
		// enter this job, so their independent watcher survives service death.
		command.Stdin = nil
		stdin, pipeErr := command.StdinPipe()
		if pipeErr != nil {
			return nil, pipeErr
		}
		if err = command.Start(); err != nil {
			stdin.Close()
			return nil, errors.New("fixed user worker failed")
		}
		job, ownershipErr := ownWorker(command.Process.Pid)
		if ownershipErr != nil {
			stdin.Close()
			command.Process.Kill()
			command.Wait()
			return nil, errors.New("fixed user worker ownership unavailable")
		}
		written := make(chan error, 1)
		go func() {
			_, writeErr := stdin.Write(input)
			closeErr := stdin.Close()
			written <- errors.Join(writeErr, closeErr)
		}()
		waitErr := command.Wait()
		writeErr := <-written
		closeErr := job.Close()
		if waitErr != nil || writeErr != nil || closeErr != nil {
			return nil, errors.New("fixed user worker exit unconfirmed")
		}
		return output.Bytes(), nil
	}
	if err := command.Run(); err != nil {
		return nil, errors.New("fixed helper failed; private stderr omitted")
	}
	return output.Bytes(), nil
}
func fixedCommand(ctx context.Context, image, entry string, userToken windows.Token) (*exec.Cmd, error) {
	command := exec.CommandContext(ctx, image, entry)
	command.Dir = filepath.Dir(image)
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	if userToken != 0 {
		environment, err := userToken.Environ(false)
		if err != nil {
			return nil, err
		}
		command.Env = safeWorkerEnvironment(environment, filepath.Dir(image))
		command.SysProcAttr.Token = syscall.Token(userToken)
	} else {
		command.Env = safeWorkerEnvironment(windows.Environ(), filepath.Dir(image))
	}
	return command, nil
}
func safeWorkerEnvironment(environment []string, helperDir string) []string {
	allowed := map[string]bool{"SYSTEMROOT": true, "WINDIR": true, "USERPROFILE": true, "APPDATA": true, "LOCALAPPDATA": true, "TEMP": true, "TMP": true, "USERNAME": true, "USERDOMAIN": true, "PROGRAMDATA": true, "PROGRAMFILES": true, "PROGRAMFILES(X86)": true, "SYSTEMDRIVE": true}
	result := []string{}
	systemRoot := `C:\Windows`
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if ok && allowed[strings.ToUpper(key)] {
			result = append(result, key+"="+value)
			if strings.EqualFold(key, "SystemRoot") {
				systemRoot = value
			}
		}
	}
	return append(result, "PATH="+filepath.Join(systemRoot, "System32")+";"+helperDir)
}
