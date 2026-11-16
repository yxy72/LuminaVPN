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
	"netlaunch/internal/policy"
	p "netlaunch/internal/serviceprotocol"
)

type macRunStop interface {
	Matches(string, os.FileInfo) bool
	Request(context.Context) error
	WaitForStoppedReport(context.Context) error
	RecoverVerified(context.Context) error
	Close() error
}

type macRunCompanyControl interface {
	SetMacCompany(context.Context, string, uint64, bool, bool) error
	AuthenticateMacCompany(context.Context, string, string, uint64) error
}

type macRunPersonalControl interface {
	SetMacPersonal(context.Context, string, uint64, bool, bool) error
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
	start    func(context.Context, string, string, time.Duration, policy.ChannelIntent) error
	auth     func(context.Context, string, string) error
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
		start: app.StartMacNetworkWithIntent,
		auth:  app.AuthenticateMacCompany,
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
	if identityChanged || n.current.stop != next.stop || n.current.status.Phase != next.status.Phase ||
		n.current.status.ChannelGeneration != next.status.ChannelGeneration || n.current.status.AppliedGeneration != next.status.AppliedGeneration ||
		n.current.status.DarwinCompanyControl != next.status.DarwinCompanyControl ||
		n.current.status.DarwinPersonalControl != next.status.DarwinPersonalControl {
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
		return m.Start != nil
	case p.AuthBegin:
		return m.BeginAuth != nil
	case p.ChannelsSet:
		return m.RunRef != "" && m.Channels != nil
	case p.TakeoverStop, p.ExitRestore:
		return m.RunRef != ""
	default:
		return false
	}
}

func macChannelsSettled(r macRunReport) bool {
	s := r.status
	return r.reported && r.identity != nil && !r.stop && s.TakeoverActive &&
		s.ChannelGeneration != 0 && s.ChannelGeneration == s.AppliedGeneration &&
		s.DesiredChannels != nil && s.AppliedChannels != nil && *s.DesiredChannels == *s.AppliedChannels
}

func macCompanyEligible(r macRunReport) bool {
	return r.status.DarwinCompanyControl && macChannelsSettled(r)
}

func macPersonalEligible(r macRunReport) bool {
	return r.status.DarwinPersonalControl && macChannelsSettled(r)
}

func savedMacDesired(r macRunReport) p.DesiredChannels {
	if !r.reported {
		return p.DesiredChannels{}
	}
	if intent := r.status.DesiredChannels; intent != nil {
		return p.DesiredChannels{Company: intent.Company, Personal: intent.Personal}
	}
	// Runs made by the legacy CLI used both channels.
	return p.DesiredChannels{Company: true, Personal: true}
}

func savedMacChannel(r macRunReport, channel string, desired bool) p.Channel {
	view := p.Channel{Desired: desired, State: "unknown", Route: "unknown"}
	h, ok := r.status.Channels[channel]
	if !r.reported || !ok {
		return view
	}
	if state := oneOf(h.State, "unknown", "ready", "unavailable", "degraded"); state != "unknown" {
		view.State = state + "_reported"
	}
	view.Reason = oneOf(h.Reason, "", reasonCodes...)
	applied := r.status.AppliedChannels
	if !r.stop && r.status.TakeoverActive && applied != nil &&
		r.status.ChannelGeneration != 0 && r.status.ChannelGeneration == r.status.AppliedGeneration {
		switch {
		case channel == "company" && !desired && !applied.Company && h.State == "ready" && h.Reason == "disabled_blocked" && h.PathState == "blocked":
			view.Route, view.Reason = "blocked_reported", h.Reason
		case channel == "personal" && !desired && !applied.Personal && h.State == "ready" && h.Reason == "disabled_direct" && h.PathState == "physical_direct":
			view.Route, view.Reason = "direct_reported", h.Reason
		case channel == "personal" && desired && applied.Personal && r.status.PersonalFallback && h.State == "degraded" && h.Reason == "all_candidates_failed" && h.PathState == "physical_direct":
			view.Route, view.Reason = "direct_reported", h.Reason
		}
	}
	if view.Route == "unknown" && (view.Reason == "disabled_blocked" || view.Reason == "disabled_direct" || view.Reason == "all_candidates_failed") {
		view.State, view.Reason = "unknown", "intent_pending"
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
	desired := savedMacDesired(r)
	s := p.Snapshot{
		ProtocolVersion: 1, ServiceState: "local", TakeoverState: "idle", ProfileID: w.profile,
		Revision: n.revision, RunRef: n.runRef, OperationID: w.activeID,
		Desired: desired,
		Company: savedMacChannel(r, "company", desired.Company), Personal: savedMacChannel(r, "personal", desired.Personal),
		RecoveryRequired:   n.lost.present || r.present && !n.restored() && !n.stoppedReport(),
		Restored:           n.restored(),
		MacCompanyControl:  w.activeID == "" && macCompanyEligible(r),
		MacPersonalControl: w.activeID == "" && macPersonalEligible(r),
	}
	switch {
	case s.Restored:
		s.TakeoverState = "restored"
	case n.lost.present || r.present && (!r.reported || r.identity == nil):
		s.TakeoverState = "unconfirmed"
	case r.present:
		if phase := oneOf(r.status.Phase, "", "prepared", "preparing", "connecting", "reconnecting", "starting",
			"ready", "managed", "degraded", "authentication_required", "company_unavailable", "personal_unavailable",
			"network_unavailable", "stopping", "stopped", "recovery_failed"); phase != "" {
			s.TakeoverState = phase + "_reported"
		} else {
			s.TakeoverState = "unconfirmed"
		}
	}
	if w.activeID != "" {
		switch operation := w.records[w.activeID].operation; operation.Kind {
		case p.TakeoverStart, p.TakeoverStop, p.ExitRestore, p.AuthBegin, p.ChannelsSet:
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
	active := w.records[w.activeID]
	stop := m.Kind == p.TakeoverStop || m.Kind == p.ExitRestore
	priority := stop && w.activeCancel != nil &&
		active.operation.RunRef == m.RunRef && m.RunRef != "" &&
		(active.operation.Kind == p.ChannelsSet || active.operation.Kind == p.AuthBegin)
	previous, found, err := w.checkSubmitLocked(m.RequestID, digest)
	var busy *Error
	if found || err != nil && (!priority || !errors.As(err, &busy) || busy.Code != "PROFILE_BUSY") {
		return previous, err
	}
	n := w.network
	n.observe(w.commands.Profile)
	idleAuth := m.Kind == p.AuthBegin && m.RunRef == ""
	// STOP keeps its exact run binding when a Company operation completes
	// between the renderer's snapshot and submission.
	if (m.ExpectedRevision != n.revision && (!stop || m.ExpectedRevision == 0 || m.ExpectedRevision > n.revision)) ||
		(!idleAuth && m.RunRef != n.runRef) {
		return p.Operation{}, &Error{Code: "REVISION_CONFLICT", Message: "The local run changed. Refresh its state before retrying.", Retryable: true}
	}
	var target macRunStop
	var phase string
	var personalChange bool
	if m.Kind == p.TakeoverStart || idleAuth {
		if n.lost.present || n.current.present && !n.stoppedReport() && !n.restored() {
			return p.Operation{}, unavailable("RECOVERY_REQUIRED", "The previous run's state must be resolved before starting.")
		}
		phase = "starting"
		if m.Kind == p.AuthBegin {
			phase = "authenticating"
		}
	} else {
		if m.Kind == p.AuthBegin {
			if !macCompanyEligible(n.current) {
				return p.Operation{}, unavailable("MAC_COMPANY_UNAVAILABLE", "The selected run does not support changing the company channel.")
			}
			if !n.current.status.AppliedChannels.Company {
				return p.Operation{}, unavailable("INVALID_PARAMS", "The current company channel must be enabled for authentication.")
			}
		}
		if m.Kind == p.ChannelsSet {
			var err error
			personalChange, err = macChannelChange(n.current, *m.Channels)
			if err != nil {
				return p.Operation{}, err
			}
		}
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
			return p.Operation{}, unavailable("RUN_UNCONFIRMED", "The selected run could not be bound.")
		}
		phase = "waiting_for_stop_report"
		if m.Kind == p.ExitRestore {
			phase = "recovering"
		} else if personalChange {
			if _, ok := target.(macRunPersonalControl); !ok {
				_ = target.Close()
				return p.Operation{}, unavailable("MAC_PERSONAL_UNAVAILABLE", "The selected run cannot change the personal channel.")
			}
			phase = "applying_personal"
		} else if m.Kind == p.ChannelsSet || m.Kind == p.AuthBegin {
			if _, ok := target.(macRunCompanyControl); !ok {
				_ = target.Close()
				return p.Operation{}, unavailable("MAC_COMPANY_UNAVAILABLE", "The selected run cannot change the company channel.")
			}
			phase = "applying_company"
			if m.Kind == p.AuthBegin {
				phase = "authenticating"
			}
		}
	}
	if err := ctx.Err(); err != nil {
		if target != nil {
			_ = target.Close()
		}
		return p.Operation{}, err
	}
	n.revision++
	var prior <-chan struct{}
	if priority {
		prior = active.done
		w.activeCancel()
	}
	op := w.enqueueLocked(m.RequestID, digest, m.Kind, phase, m.RunRef, n.revision)
	job, cancel := context.WithCancel(w.ctx)
	w.activeCancel = cancel
	go w.executeNetwork(job, cancel, m, target, n.current, prior, personalChange)
	return op, nil
}

func macChannelChange(r macRunReport, desired p.DesiredChannels) (personal bool, err error) {
	current := savedMacDesired(r)
	personal = desired.Personal != current.Personal && desired.Company == current.Company
	if personal {
		if !macPersonalEligible(r) {
			return false, unavailable("MAC_PERSONAL_UNAVAILABLE", "The selected run does not have a frozen personal channel available.")
		}
		return true, nil
	}
	if macChannelsSettled(r) && (desired.Company == current.Company || desired.Personal != current.Personal) {
		return false, unavailable("INVALID_PARAMS", "Change exactly one channel for the current run.")
	}
	if !macCompanyEligible(r) {
		return false, unavailable("MAC_COMPANY_UNAVAILABLE", "The selected run does not support changing the company channel.")
	}
	return false, nil
}

func (w *localWorkspace) executeNetwork(job context.Context, done context.CancelFunc, m p.Mutation, target macRunStop, bound macRunReport, prior <-chan struct{}, personalChange bool) {
	defer done()
	var err error
	var phase, failureCode string
	switch m.Kind {
	case p.TakeoverStart:
		ctx, cancel := context.WithTimeout(job, 8*time.Minute)
		intent := policy.ChannelIntent{Company: m.Start.Channels.Company, Personal: m.Start.Channels.Personal}
		err = w.network.start(ctx, w.commands.Profile, w.commands.Runtime, time.Duration(m.Start.ValidationSeconds)*time.Second, intent)
		cancel()
		phase, failureCode = "ready_reported", "MAC_START_FAILED"
	case p.AuthBegin:
		ctx, cancel := context.WithTimeout(job, 6*time.Minute)
		if target == nil {
			err = w.network.auth(ctx, w.commands.Profile, w.commands.Runtime)
		} else {
			err = target.(macRunCompanyControl).AuthenticateMacCompany(ctx, w.commands.Profile, w.commands.Runtime, bound.status.AppliedGeneration)
		}
		cancel()
		phase, failureCode = "authenticated", "MAC_AUTH_FAILED"
	case p.ChannelsSet:
		ctx, cancel := context.WithTimeout(job, 4*time.Minute)
		if personalChange {
			err = target.(macRunPersonalControl).SetMacPersonal(ctx, m.RequestID, bound.status.AppliedGeneration, m.Channels.Company, m.Channels.Personal)
			phase, failureCode = "personal_applied", "MAC_PERSONAL_UNCONFIRMED"
		} else {
			err = target.(macRunCompanyControl).SetMacCompany(ctx, m.RequestID, bound.status.AppliedGeneration, m.Channels.Company, m.Channels.Personal)
			phase, failureCode = "company_applied", "MAC_COMPANY_UNCONFIRMED"
		}
		cancel()
	case p.TakeoverStop:
		ctx, cancel := context.WithTimeout(job, 20*time.Second)
		err = target.Request(ctx)
		if err == nil {
			err = target.WaitForStoppedReport(ctx)
		}
		cancel()
		phase, failureCode = "stopped_reported", "MAC_STOP_UNCONFIRMED"
	case p.ExitRestore:
		ctx, cancel := context.WithTimeout(job, 4*time.Minute)
		if prior != nil {
			err = target.Request(ctx)
		}
		if err == nil {
			err = target.RecoverVerified(ctx)
		}
		cancel()
		phase, failureCode = "restored", "MAC_RECOVERY_UNCONFIRMED"
	}
	// A priority stop publishes its fence immediately, but the workspace
	// remains occupied until the canceled action has released its target.
	if prior != nil {
		<-prior
	}
	if target != nil {
		_ = target.Close()
	}
	if err == nil && job.Err() != nil {
		err = job.Err()
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
		op.Error = &p.Error{Code: failureCode, Message: "The local operation could not be confirmed."}
		if errors.Is(err, app.ErrMacAuthenticationRequired) {
			op.Error = &p.Error{Code: "MAC_AUTH_REQUIRED", Message: "Authenticate in the local Terminal before starting the company channel.", Retryable: true}
		}
	} else if m.Kind == p.ExitRestore {
		op.Restored = true
	}
	w.completeLocked(m.RequestID, record)
}
