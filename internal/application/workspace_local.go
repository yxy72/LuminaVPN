package application

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"sync"
	"time"

	"netlaunch/internal/app"
	p "netlaunch/internal/serviceprotocol"
)

// localWorkspace serializes local desktop operations on macOS. Workspace edits
// and network controls share a queue, but have separate authorization paths.
type localWorkspace struct {
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	closed   bool
	commands app.DesktopCommands
	profile  string
	active   chan struct{}
	activeID string
	order    []string
	records  map[string]localWorkspaceRecord
	network  *macNetwork
}

type localWorkspaceRecord struct {
	operation p.Operation
	digest    [sha256.Size]byte
}

func (d *Desktop) EnableLocalWorkspace(ctx context.Context) {
	if runtime.GOOS != "darwin" || os.Geteuid() == 0 || d.localWorkspace != nil {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	d.localWorkspace = &localWorkspace{
		ctx: ctx, cancel: cancel, profile: d.ClientProfileID(),
		commands: app.DesktopCommands{Profile: d.Profile, Runtime: d.Runtime},
		records:  make(map[string]localWorkspaceRecord),
	}
}

func (d *Desktop) CloseLocalWorkspace() {
	if d.localWorkspace == nil {
		return
	}
	w := d.localWorkspace
	w.mu.Lock()
	w.closed = true
	active := w.active
	w.mu.Unlock()
	w.cancel()
	if active != nil {
		<-active
	}
}

func (w *localWorkspace) busy() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.active != nil
}

func (w *localWorkspace) operation(id string) (p.Operation, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	record, ok := w.records[id]
	if !ok {
		return p.Operation{}, unavailable("OPERATION_NOT_FOUND", "The workspace operation is no longer available.")
	}
	return record.operation, nil
}

func (w *localWorkspace) submit(id string, work p.WorkspacePayload) (p.Operation, error) {
	raw, err := json.Marshal(work)
	if err != nil {
		return p.Operation{}, unavailable("INVALID_PARAMS", "Invalid workspace operation.")
	}
	digest := sha256.Sum256(raw)
	w.mu.Lock()
	defer w.mu.Unlock()
	if previous, found, err := w.checkSubmitLocked(id, digest); found || err != nil {
		return previous, err
	}
	op := w.enqueueLocked(id, digest, p.Workspace, "running", "", 0)
	go w.execute(id, work)
	return op, nil
}

func (w *localWorkspace) checkSubmitLocked(id string, digest [sha256.Size]byte) (p.Operation, bool, error) {
	if previous, exists := w.records[id]; exists {
		if previous.digest != digest {
			return p.Operation{}, true, unavailable("REQUEST_CONFLICT", "The request identifier belongs to a different operation.")
		}
		return previous.operation, true, nil
	}
	if w.closed || w.ctx.Err() != nil {
		return p.Operation{}, false, unavailable("CLIENT_UNAVAILABLE", "The desktop connection is closing.")
	}
	if w.active != nil {
		return p.Operation{}, false, &Error{Code: "PROFILE_BUSY", Message: "Another operation for this profile is still running.", Retryable: true}
	}
	return p.Operation{}, false, nil
}

func (w *localWorkspace) enqueueLocked(id string, digest [sha256.Size]byte, kind p.Kind, phase, runRef string, revision uint64) p.Operation {
	const maxRetained = 64
	if len(w.order) == maxRetained {
		delete(w.records, w.order[0])
		w.order = w.order[1:]
	}
	now := time.Now().UTC()
	op := p.Operation{ID: id, RequestID: id, ProfileID: w.profile, Kind: kind, Phase: phase, RunRef: runRef, Revision: revision, Created: now, Updated: now}
	w.order = append(w.order, id)
	w.records[id] = localWorkspaceRecord{operation: op, digest: digest}
	w.active = make(chan struct{})
	w.activeID = id
	return op
}

func (w *localWorkspace) execute(id string, work p.WorkspacePayload) {
	ctx, cancel := context.WithTimeout(w.ctx, 2*time.Minute)
	_, err := w.commands.Execute(ctx, work)
	cancel()
	w.mu.Lock()
	defer w.mu.Unlock()
	record := w.records[id]
	record.operation.Completed = true
	record.operation.Phase = "completed"
	record.operation.Updated = time.Now().UTC()
	if err != nil {
		record.operation.Phase = "failed"
		record.operation.Error = &p.Error{Code: "CLIENT_OPERATION_FAILED", Message: "The local workspace operation could not be completed."}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			record.operation.Error.Code = "WORKSPACE_INTERRUPTED"
		}
	}
	if w.network != nil {
		w.network.revision++
	}
	w.completeLocked(id, record)
}

func (w *localWorkspace) completeLocked(id string, record localWorkspaceRecord) {
	w.records[id] = record
	close(w.active)
	w.active, w.activeID = nil, ""
}
