package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"time"

	"netlaunch/internal/app"
	"netlaunch/internal/engine"
	p "netlaunch/internal/serviceprotocol"
)

type macRunStop interface {
	Matches(string, os.FileInfo) bool
	Request(context.Context) error
	WaitForStoppedReport(context.Context) error
	RecoverVerified(context.Context) error
	Close() error
}

type macRunReport struct {
	present, stop, reported bool
	path                    string
	identity                os.FileInfo
	status                  engine.Status
}

func macSavedRun(profile string) macRunReport {
	run, status, present, stop, err := app.DesktopSavedStatus(profile)
	observation := macRunReport{present: present, stop: stop, reported: present && err == nil, path: run, status: status}
	if run != "" {
		if info, err := os.Lstat(run); err == nil && info.IsDir() {
			observation.identity = info
		}
	}
	return observation
}

func (r macRunReport) sameRun(other macRunReport) bool {
	return r.identity != nil && other.identity != nil && r.path == other.path && os.SameFile(r.identity, other.identity)
}

type macNetwork struct {
	start    func(context.Context, string, string, time.Duration) error
	bind     func(context.Context, string) (macRunStop, error)
	inspect  func(string) macRunReport
	revision uint64
	current  macRunReport
	verified macRunReport
	lost     macRunReport
	runRef   string
}

// EnableLocalNetwork enables the ordinary-user Mac desktop adapter. Windows
// continues to route lifecycle operations through the installed service.
func (d *Desktop) EnableLocalNetwork(ctx context.Context) {
	d.EnableLocalWorkspace(ctx)
	if d.localWorkspace == nil || d.MacClientEnabled() {
		return
	}
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return
	}
	d.localWorkspace.network = &macNetwork{
		start: app.StartMacNetwork,
		bind: func(ctx context.Context, profile string) (macRunStop, error) {
			run, err := app.BindCurrentRunStop(ctx, profile)
			if err != nil {
				return nil, err
			}
			return run, nil
		},
		inspect:  macSavedRun,
		revision: 1 + (binary.LittleEndian.Uint64(seed[:]) & ((1 << 48) - 1)),
	}
}

func (d *Desktop) MacClientEnabled() bool {
	return d.localWorkspace != nil && d.localWorkspace.network != nil
}

func (n *macNetwork) observe(profile string) {
	next := n.inspect(profile)
	if n.current.present && !next.present && !n.current.sameRun(n.verified) {
		// A missing current pointer cannot prove restoration of a run that
		// this bridge already observed.
		n.lost = n.current
	}
	if next.present {
		n.lost = macRunReport{}
	}
	identityChanged := next.present != n.current.present || (next.present &&
		(next.path != n.current.path || (next.identity != nil || n.current.identity != nil) && !next.sameRun(n.current)))
	if identityChanged || n.current.stop != next.stop || n.current.status.Phase != next.status.Phase {
		n.revision++
	}
	if identityChanged {
		n.runRef = ""
		if next.identity != nil {
			n.runRef = "mac-run-" + strconv.FormatUint(n.revision, 16)
		}
	}
	n.current = next
}

func (n *macNetwork) restored() bool { return n.current.sameRun(n.verified) }

func (n *macNetwork) stoppedReport() bool {
	return n.current.identity != nil && n.current.reported && n.current.status.Phase == "stopped"
}

func validMacNetworkMutation(m p.Mutation) bool {
	switch m.Kind {
	case p.TakeoverStart:
		// Mutation.Validate already checks daily vs. the validation window.
		return m.Start != nil && m.Start.Channels.Company && m.Start.Channels.Personal
	case p.TakeoverStop, p.ExitRestore:
		return m.RunRef != ""
	default:
		return false
	}
}

func savedMacChannel(r macRunReport, channel string) p.Channel {
	view := p.Channel{Desired: true, State: "unknown", Route: "unknown"}
	if !r.reported {
		return view
	}
	if h, ok := r.status.Channels[channel]; ok {
		if state := oneOf(h.State, "unknown", "ready", "unavailable"); state != "unknown" {
			view.State = state + "_reported"
		}
		view.Reason = oneOf(h.Reason, "", reasonCodes...)
	}
	return view
}

func (w *localWorkspace) networkSnapshot(ctx context.Context) (p.Snapshot, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return p.Snapshot{}, err
	}
	n := w.network
	n.observe(w.commands.Profile)
	r := n.current
	s := p.Snapshot{
		ProtocolVersion: 1, ServiceState: "local", TakeoverState: "idle", ProfileID: w.profile,
		Revision: n.revision, RunRef: n.runRef, OperationID: w.activeID,
		Desired: p.DesiredChannels{Company: true, Personal: true},
		Company: savedMacChannel(r, "company"), Personal: savedMacChannel(r, "personal"),
		RecoveryRequired: n.lost.present || r.present && !n.restored() && !n.stoppedReport(),
		Restored:         n.restored(),
	}
	switch {
	case s.Restored:
		s.TakeoverState = "restored"
	case n.lost.present || r.present && (!r.reported || r.identity == nil):
		s.TakeoverState = "unconfirmed"
	case r.present:
		if phase := oneOf(r.status.Phase, "", "prepared", "preparing", "connecting", "reconnecting", "starting",
			"ready", "degraded", "authentication_required", "company_unavailable", "personal_unavailable",
			"network_unavailable", "stopping", "stopped", "recovery_failed"); phase != "" {
			s.TakeoverState = phase + "_reported"
		} else {
			s.TakeoverState = "unconfirmed"
		}
	}
	if w.activeID != "" {
		switch operation := w.records[w.activeID].operation; operation.Kind {
		case p.TakeoverStart, p.TakeoverStop, p.ExitRestore:
			s.TakeoverState = operation.Phase
		}
	}
	return s, nil
}

func (w *localWorkspace) submitNetwork(ctx context.Context, m p.Mutation) (p.Operation, error) {
	if m.Validate() != nil || m.ProfileID != w.profile || !validMacNetworkMutation(m) {
		return p.Operation{}, unavailable("INVALID_PARAMS", "This local network operation is unavailable or invalid.")
	}
	if err := ctx.Err(); err != nil {
		return p.Operation{}, err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return p.Operation{}, unavailable("INVALID_PARAMS", "Invalid network operation.")
	}
	digest := sha256.Sum256(raw)
	w.mu.Lock()
	defer w.mu.Unlock()
	if previous, found, err := w.checkSubmitLocked(m.RequestID, digest); found || err != nil {
		return previous, err
	}
	n := w.network
	n.observe(w.commands.Profile)
	if m.ExpectedRevision != n.revision || m.RunRef != n.runRef {
		return p.Operation{}, &Error{Code: "REVISION_CONFLICT", Message: "The local run changed. Refresh its state before retrying.", Retryable: true}
	}
	var target macRunStop
	var phase string
	if m.Kind == p.TakeoverStart {
		if n.lost.present || n.current.present && !n.stoppedReport() && !n.restored() {
			return p.Operation{}, unavailable("RECOVERY_REQUIRED", "The previous run's state must be resolved before starting.")
		}
		phase = "starting"
	} else {
		// Resolve and retain the exact run before dispatch. A changed profile
		// pointer must not authorize STOP or recovery for a newer run.
		target, err = n.bind(ctx, w.commands.Profile)
		if err == nil && (target == nil || !target.Matches(n.current.path, n.current.identity)) {
			if target != nil {
				_ = target.Close()
			}
			err = errors.New("bound run changed")
		}
		if err != nil {
			return p.Operation{}, unavailable("RUN_UNCONFIRMED", "The selected run could not be bound for recovery.")
		}
		phase = "waiting_for_stop_report"
		if m.Kind == p.ExitRestore {
			phase = "recovering"
		}
	}
	if err := ctx.Err(); err != nil {
		if target != nil {
			_ = target.Close()
		}
		return p.Operation{}, err
	}
	n.revision++
	op := w.enqueueLocked(m.RequestID, digest, m.Kind, phase, m.RunRef, n.revision)
	go w.executeNetwork(m, target, n.current)
	return op, nil
}

func (w *localWorkspace) executeNetwork(m p.Mutation, target macRunStop, bound macRunReport) {
	if target != nil {
		defer target.Close()
	}
	var err error
	var phase, failureCode string
	switch m.Kind {
	case p.TakeoverStart:
		ctx, cancel := context.WithTimeout(w.ctx, 8*time.Minute)
		err = w.network.start(ctx, w.commands.Profile, w.commands.Runtime, time.Duration(m.Start.ValidationSeconds)*time.Second)
		cancel()
		phase, failureCode = "ready_reported", "MAC_START_FAILED"
	case p.TakeoverStop:
		ctx, cancel := context.WithTimeout(w.ctx, 20*time.Second)
		err = target.Request(ctx)
		if err == nil {
			err = target.WaitForStoppedReport(ctx)
		}
		cancel()
		phase, failureCode = "stopped_reported", "MAC_STOP_UNCONFIRMED"
	case p.ExitRestore:
		ctx, cancel := context.WithTimeout(w.ctx, 4*time.Minute)
		err = target.RecoverVerified(ctx)
		cancel()
		phase, failureCode = "restored", "MAC_RECOVERY_UNCONFIRMED"
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	n := w.network
	if err == nil && m.Kind == p.ExitRestore {
		n.verified = bound
		if n.lost.sameRun(bound) {
			n.lost = macRunReport{}
		}
	}
	n.observe(w.commands.Profile)
	n.revision++
	record := w.records[m.RequestID]
	op := &record.operation
	op.Completed, op.Phase, op.Revision, op.Updated = true, phase, n.revision, time.Now().UTC()
	if err != nil {
		if errors.Is(err, context.Canceled) || (m.Kind != p.TakeoverStop && errors.Is(err, context.DeadlineExceeded)) {
			failureCode = "MAC_OPERATION_INTERRUPTED"
		}
		op.Phase = "failed"
		op.Error = &p.Error{Code: failureCode, Message: "The local network operation could not be confirmed."}
	} else if m.Kind == p.ExitRestore {
		op.Restored = true
	}
	w.completeLocked(m.RequestID, record)
}
