//go:build windows

package app

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"sync"
	"time"

	"netlaunch/internal/auth"
	"netlaunch/internal/engine"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	p "netlaunch/internal/serviceprotocol"
	"netlaunch/internal/winservice"
)

type serviceConversation interface {
	ReadEvent(context.Context) (winservice.UserAuthEvent, error)
	Respond(context.Context, winservice.UserAuthResponse) error
	Close() error
}
type servicePreferences interface {
	Load() (p.SettingsPayload, error)
	Save(p.SettingsPayload) error
}
type serviceRestorations interface {
	Save(winservice.Binding, string, json.RawMessage) (string, error)
	Verify(winservice.Binding) (bool, error)
}
type serviceBackendDependencies struct {
	lifecycle    func(context.Context, winservice.LifecycleAction, []byte) ([]byte, error)
	snapshot     func(context.Context, winservice.VerifiedPrincipal, winservice.Binding) ([]byte, error)
	workspace    func(context.Context, winservice.VerifiedPrincipal, winservice.Binding, p.WorkspacePayload) ([]byte, error)
	startAuth    func(context.Context, winservice.VerifiedPrincipal, winservice.Binding, winservice.UserAuthNetworkBinding) (serviceConversation, error)
	pristine     func(winservice.Binding) (bool, error)
	prefs        servicePreferences
	restorations serviceRestorations
	now          func() time.Time
}
type fixedLifecycleBackend struct {
	owners            winservice.OwnershipStore
	deps              serviceBackendDependencies
	broker            *winservice.Broker
	mu                sync.Mutex
	settings          p.SettingsPayload
	saved             policy.Config
	running           policy.Config
	frozenDigest      string
	challenge         *p.Challenge
	conversation      serviceConversation
	authGeneration    string
	exiting           bool
	sealed            bool
	enrollmentBarrier bool
	stopGeneration    uint64
	workers           int
	hostIdentity      platform.Identity
	enrollmentFailure bool
}

// NewWindowsServiceHost opens only the reviewed installed service/catalog.
// Missing protected state is unavailable; this never substitutes a mock host.
func NewWindowsServiceHost() (*winservice.Host, error) {
	return winservice.NewInstalledHost(func(installation winservice.Installation, owners winservice.OwnershipStore, binding winservice.Binding) (winservice.Backend, error) {
		executor, err := winservice.NewFixedExecutor(installation)
		if err != nil {
			return nil, err
		}
		preferences, err := winservice.OpenClientSettingsStore(binding)
		if err != nil {
			return nil, err
		}
		settings, err := preferences.Load()
		if err != nil {
			return nil, err
		}
		restorations, err := winservice.OpenRestorationStore(binding)
		if err != nil {
			return nil, err
		}
		hostIdentity, err := platform.Process(os.Getpid())
		if err != nil || hostIdentity.PID != os.Getpid() || hostIdentity.Birth == "" {
			return nil, backendFailure("SERVICE_IDENTITY_UNAVAILABLE")
		}
		// Authentication requires a freshly verified physical socket plan;
		// the user-worker image receives no broad WFP exemption.
		return &fixedLifecycleBackend{owners: owners, settings: settings, hostIdentity: hostIdentity, deps: serviceBackendDependencies{lifecycle: executor.Lifecycle, snapshot: executor.UserSnapshot, workspace: executor.UserWorkspace, startAuth: func(ctx context.Context, v winservice.VerifiedPrincipal, binding winservice.Binding, network winservice.UserAuthNetworkBinding) (serviceConversation, error) {
			return executor.StartUserAuthentication(ctx, v, binding, network)
		}, pristine: winservice.PristineOwnedRuns, prefs: preferences, restorations: restorations, now: time.Now}}, nil
	})
}
func (b *fixedLifecycleBackend) AttachBroker(broker *winservice.Broker) { b.broker = broker }

// SealForShutdown is called only by the service-owned SCM shutdown path.
// Ordinary stop/exit and enrollment recovery use temporary barriers instead.
func (b *fixedLifecycleBackend) SealForShutdown() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sealed = true
	b.exiting = true
	b.stopGeneration++
}
func (b *fixedLifecycleBackend) barrierClosedLocked() bool {
	return b.exiting || b.sealed || b.enrollmentBarrier || b.enrollmentFailure
}
func backendFailure(code string) error {
	return &p.Error{Code: code, Message: "The service could not verify this operation."}
}
func currentServiceReference(binding winservice.Binding) (engine.ServiceRunReference, error) {
	r := engine.ServiceRunReference{ProfileID: binding.ProfileID, RunID: binding.PreparedRunID, SpecDigest: binding.SpecDigest, BindingRunRef: binding.RunRef, ServiceInstance: binding.ServiceInstance}
	return r, r.Validate()
}
func (b *fixedLifecycleBackend) current(binding winservice.Binding) (winservice.Binding, error) {
	actual, err := b.owners.Lookup(binding.ProfileID)
	if err != nil || actual.OwnerSID != binding.OwnerSID || actual.LogonSID != binding.LogonSID || actual.AuthenticationID != binding.AuthenticationID || actual.SessionID != binding.SessionID || actual.LogonEpoch != binding.LogonEpoch || actual.ExecutorSID != binding.ExecutorSID || actual.ServiceInstance != binding.ServiceInstance || actual.RunRef != binding.RunRef {
		return winservice.Binding{}, backendFailure("OWNERSHIP_UNAVAILABLE")
	}
	return actual, nil
}
func (b *fixedLifecycleBackend) invoke(ctx context.Context, action winservice.LifecycleAction, payload any, result any) error {
	input, err := json.Marshal(payload)
	if err != nil {
		return backendFailure("INVALID_SERVICE_DATA")
	}
	defer clear(input)
	output, err := b.deps.lifecycle(ctx, action, input)
	defer clear(output)
	if err != nil {
		return backendFailure("FIXED_HELPER_FAILED")
	}
	if decodeServiceHelperJSON(output, result) != nil {
		return backendFailure("INVALID_HELPER_RESPONSE")
	}
	return nil
}
func (b *fixedLifecycleBackend) userSnapshot(ctx context.Context, v winservice.VerifiedPrincipal, binding winservice.Binding) (ServiceUserSnapshotData, error) {
	b.mu.Lock()
	if b.barrierClosedLocked() {
		b.mu.Unlock()
		return ServiceUserSnapshotData{}, backendFailure("STOP_BARRIER")
	}
	b.workers++
	b.mu.Unlock()
	defer func() { b.mu.Lock(); b.workers--; b.mu.Unlock() }()
	output, err := b.deps.snapshot(ctx, v, binding)
	defer clear(output)
	if err != nil {
		return ServiceUserSnapshotData{}, backendFailure("USER_PROFILE_UNAVAILABLE")
	}
	var data ServiceUserSnapshotData
	if decodeServiceHelperJSON(output, &data) != nil || data.SavedPolicy.ValidateForStorage() != nil || data.Policy.ValidateForStorage() != nil || !validRevision(data.PolicyRevision) || len(data.EffectiveDigest) != 64 {
		return ServiceUserSnapshotData{}, backendFailure("INVALID_USER_SNAPSHOT")
	}
	if data.Session != nil && (data.Session.Validate(data.Policy.VPN) != nil || !data.Session.ValidAt(b.deps.now())) {
		data.Session.Cookie = ""
		data.Session = nil
	}
	b.mu.Lock()
	b.saved = data.SavedPolicy
	b.settings.OfficeOverrides = protocolOverrides(data.SavedPolicy.OfficeOverrides)
	b.settings.HomeOverrides = protocolOverrides(data.SavedPolicy.HomeOverrides)
	b.mu.Unlock()
	return data, nil
}
func protocolOverrides(values []policy.Override) []p.Override {
	out := make([]p.Override, 0, len(values))
	for _, value := range values {
		out = append(out, p.Override{Type: value.Type, Value: value.Value, Target: value.Target})
	}
	return out
}
func policyOverrides(values []p.Override) []policy.Override {
	out := make([]policy.Override, 0, len(values))
	for _, value := range values {
		out = append(out, policy.Override{Type: value.Type, Value: value.Value, Target: value.Target})
	}
	return out
}
func clearUserSession(data *ServiceUserSnapshotData) {
	if data.Session != nil {
		data.Session.Cookie = ""
		data.Session = nil
	}
}
func (b *fixedLifecycleBackend) status(ctx context.Context, binding winservice.Binding) (engine.ServiceStatusResult, error) {
	r, err := currentServiceReference(binding)
	if err != nil {
		return engine.ServiceStatusResult{}, backendFailure("PREPARED_IDENTITY_UNAVAILABLE")
	}
	var result engine.ServiceStatusResult
	if err = b.invoke(ctx, winservice.StatusLifecycle, ServiceRunPayload{ServiceRunReference: r}, &result); err != nil {
		return result, err
	}
	if result.RunID != r.RunID {
		return result, backendFailure("HELPER_IDENTITY_MISMATCH")
	}
	return result, nil
}
func sameAppliedIntent(status engine.Status, intent policy.ChannelIntent) bool {
	return status.TakeoverActive && status.ChannelGeneration > 0 && status.AppliedGeneration == status.ChannelGeneration && status.DesiredChannels != nil && status.AppliedChannels != nil && *status.DesiredChannels == intent && *status.AppliedChannels == intent && status.Phase != "stopping" && status.Phase != "stopped" && status.Phase != "recovery_failed" && status.Phase != "network_unavailable"
}
func (b *fixedLifecycleBackend) awaitApplied(ctx context.Context, binding winservice.Binding, intent policy.ChannelIntent) (engine.ServiceStatusResult, error) {
	deadline := b.deps.now().Add(60 * time.Second)
	if binding.Mode == "validation" && binding.Deadline.Before(deadline) {
		deadline = binding.Deadline
	}
	pollCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return engine.ServiceStatusResult{}, err
		}
		if !b.deps.now().Before(deadline) {
			return engine.ServiceStatusResult{}, backendFailure("INTENT_APPLY_TIMEOUT")
		}
		result, err := b.status(pollCtx, binding)
		if err != nil {
			return result, err
		}
		// A late readback cannot turn an expired transition green.
		if !b.deps.now().Before(deadline) {
			return result, backendFailure("INTENT_APPLY_TIMEOUT")
		}
		if sameAppliedIntent(result.Status, intent) {
			return result, nil
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
func (b *fixedLifecycleBackend) SnapshotForCaller(ctx context.Context, v winservice.VerifiedPrincipal, binding winservice.Binding) (p.Snapshot, error) {
	data, err := b.userSnapshot(ctx, v, binding)
	if err == nil {
		clearUserSession(&data)
	}
	return b.Snapshot(ctx, binding)
}
func (b *fixedLifecycleBackend) Snapshot(ctx context.Context, binding winservice.Binding) (p.Snapshot, error) {
	current, err := b.current(binding)
	if err != nil {
		return p.Snapshot{}, err
	}
	b.mu.Lock()
	settings := b.settings
	challenge := b.challenge
	restorations := b.deps.restorations
	b.mu.Unlock()
	view := p.Snapshot{ProtocolVersion: p.Version, ServiceState: "available", TakeoverState: "idle", ProfileID: current.ProfileID, Revision: current.Revision, RunRef: current.RunRef, Company: p.Channel{State: "off", Route: "unknown", IPv6: "unknown"}, Personal: p.Channel{State: "off", Route: "direct", IPv6: "unknown"}, Settings: &settings, Challenge: challenge}
	b.mu.Lock()
	unavailable := b.enrollmentFailure
	b.mu.Unlock()
	if unavailable {
		view.ServiceState = "unavailable"
		view.TakeoverState = "unknown"
		view.RecoveryRequired = true
		return view, nil
	}
	if current.RunRef == "" {
		if current.LastRestorationID != "" && restorations != nil {
			clean, readErr := restorations.Verify(current)
			view.Restored = readErr == nil && clean
			view.RecoveryRequired = !view.Restored
		}
		return view, nil
	}
	view.RecoveryRequired = true
	view.Restored = false
	status, err := b.status(ctx, current)
	if err != nil {
		view.TakeoverState = "unknown"
		return view, nil
	}
	view.TakeoverState = publicCode(status.Status.Phase, "starting managed ready degraded authentication_required network_unavailable stopping stopped recovery_failed prepared")
	if view.TakeoverState == "" {
		view.TakeoverState = "unknown"
	}
	if status.Status.DesiredChannels != nil {
		intent := *status.Status.DesiredChannels
		view.Desired = p.DesiredChannels{Company: intent.Company, Personal: intent.Personal}
		if intent.Environment == "home" || intent.Environment == "office" {
			view.Settings.Environment = intent.Environment
		}
	}
	view.Company = projectServiceChannel(status, "company", view.Desired.Company)
	view.Personal = projectServiceChannel(status, "personal", view.Desired.Personal)
	if status.Restored && status.Proof != nil && completeRecoveryProof(*status.Proof) {
		view.Restored = true
		view.RecoveryRequired = false
	}
	return view, nil
}
func projectServiceChannel(result engine.ServiceStatusResult, name string, desired bool) p.Channel {
	channel := p.Channel{Desired: desired, State: "unknown", Route: "unknown", IPv6: "unknown"}
	health, ok := result.Status.Channels[name]
	if result.IPv6Blocked && result.IPv6State == "blocked" && !result.IPv6CheckedAt.IsZero() {
		channel.IPv6 = "blocked"
	}
	if !ok {
		return channel
	}
	channel.State = publicCode(health.State, "ready unavailable unknown degraded")
	if channel.State == "" {
		channel.State = "unknown"
	}
	channel.Reason = publicCode(health.Reason, "disabled_blocked disabled_direct intent_pending authentication_required path_verified service_healthy service_unavailable company_ingress_unavailable vpn_not_ready no_verified_node physical_network_unavailable check_expired generation_changed selection_changed not_checked system_path_not_checked all_candidates_failed independent_health_coverage_budget_exceeded")
	if !desired && result.Status.TakeoverActive && health.Reason == "disabled_blocked" {
		channel.State = "off"
		channel.Route = "blocked"
	}
	if !desired && result.Status.TakeoverActive && health.Reason == "disabled_direct" {
		channel.State = "off"
		channel.Route = "direct"
	}
	if desired && health.State == "ready" && health.PathState == "verified" && health.ProbeScope == "system_tun" {
		if name == "company" {
			channel.Route = "vpn"
		} else {
			channel.Route = "personal"
		}
	}
	if name == "personal" && result.Status.PersonalFallback && health.PathState == "physical_direct" {
		channel.Route = "direct"
		channel.Reason = "health_evidence_unavailable"
	}
	return channel
}
func (b *fixedLifecycleBackend) Execute(ctx context.Context, a winservice.AuthorizedOperation, progress func(winservice.Progress)) (winservice.Completion, error) {
	b.mu.Lock()
	unavailable := b.enrollmentFailure
	closed := b.barrierClosedLocked()
	b.mu.Unlock()
	if unavailable {
		return winservice.Completion{}, backendFailure("BACKEND_UNAVAILABLE")
	}
	if closed {
		return winservice.Completion{}, backendFailure("STOP_BARRIER")
	}
	binding, err := b.current(a.Binding())
	if err != nil {
		return winservice.Completion{}, err
	}
	m := a.Mutation()
	switch m.Kind {
	case p.TakeoverStart:
		return b.start(ctx, a, binding, progress)
	case p.ChannelsSet:
		return b.channels(ctx, a.Principal(), binding, *m.Channels, progress)
	case p.SettingsApply:
		return b.applySettings(ctx, a.Principal(), binding, *m.Settings, progress)
	case p.ProfileApply:
		if binding.RunRef != "" {
			return winservice.Completion{}, backendFailure("STOP_REQUIRED")
		}
		if len(m.Profile.Nodes) > 0 || m.Profile.Name != "" {
			return winservice.Completion{}, backendFailure("PROFILE_FIELD_UNAVAILABLE")
		}
		data, err := b.userSnapshot(ctx, a.Principal(), binding)
		if err != nil {
			return winservice.Completion{}, err
		}
		defer clearUserSession(&data)
		raw, _ := json.Marshal(m.Profile.Policy)
		defer clear(raw)
		return b.Workspace(ctx, a.Principal(), binding, p.WorkspacePayload{Action: "apply", PolicyJSON: raw, ExpectedPolicyRevision: data.PolicyRevision}, progress)
	case p.NodeSelect:
		if m.Selection.NodeID != "auto" {
			return winservice.Completion{}, backendFailure("MANUAL_NODE_SELECTION_UNAVAILABLE")
		}
		return winservice.Completion{Revision: binding.Revision}, nil
	default:
		return winservice.Completion{}, backendFailure("UNSUPPORTED_SERVICE_OPERATION")
	}
}
func (b *fixedLifecycleBackend) start(ctx context.Context, a winservice.AuthorizedOperation, binding winservice.Binding, progress func(winservice.Progress)) (winservice.Completion, error) {
	if b.broker == nil {
		return winservice.Completion{}, backendFailure("BACKEND_UNAVAILABLE")
	}
	b.mu.Lock()
	closed := b.barrierClosedLocked()
	b.mu.Unlock()
	if closed {
		return winservice.Completion{}, backendFailure("STOP_BARRIER")
	}
	data, err := b.userSnapshot(ctx, a.Principal(), binding)
	if err != nil {
		return winservice.Completion{}, err
	}
	defer clearUserSession(&data)
	b.mu.Lock()
	environment := b.settings.Environment
	b.mu.Unlock()
	intent := policy.ChannelIntent{Company: a.Mutation().Start.Channels.Company, Personal: a.Mutation().Start.Channels.Personal, Environment: environment}
	if data.Policy.ValidateForIntent(intent) != nil {
		return winservice.Completion{}, backendFailure("RUNTIME_PREREQUISITES_UNAVAILABLE")
	}
	progress(winservice.Progress{Phase: "preparing"})
	var prepared engine.ServicePrepared
	if err = b.invoke(ctx, winservice.PrepareLifecycle, ServicePreparePayload{Binding: binding, Config: data.Policy, Nodes: data.Nodes, Mode: engine.RunMode(binding.Mode), Channels: intent, Auth: data.Session, ServiceOwnerPID: b.hostIdentity.PID, ServiceOwnerBirth: b.hostIdentity.Birth}, &prepared); err != nil {
		return winservice.Completion{}, err
	}
	if err = b.broker.BindPreparedRun(a, winservice.PreparedRun{EngineRunID: prepared.RunID, ExecutorSID: binding.ExecutorSID, SpecDigest: prepared.SpecDigest, Mode: string(prepared.Mode), Deadline: prepared.Deadline}); err != nil {
		return winservice.Completion{}, err
	}
	binding, err = b.current(binding)
	if err != nil {
		return winservice.Completion{}, err
	}
	r, err := currentServiceReference(binding)
	if err != nil {
		return winservice.Completion{}, err
	}
	b.mu.Lock()
	b.running = data.Policy
	b.frozenDigest = data.EffectiveDigest
	b.mu.Unlock()
	var served struct {
		RunID   string `json:"run_id"`
		Started bool   `json:"started"`
	}
	progress(winservice.Progress{Phase: "starting"})
	if err = b.invoke(ctx, winservice.ServeLifecycle, ServiceRunPayload{ServiceRunReference: r}, &served); err != nil {
		return winservice.Completion{}, err
	}
	if !served.Started || served.RunID != r.RunID {
		return winservice.Completion{}, backendFailure("HELPER_IDENTITY_MISMATCH")
	}
	status, err := b.awaitApplied(ctx, binding, intent)
	if err != nil {
		return winservice.Completion{}, err
	}
	if intent.Company && (prepared.CompanyPending || engine.NeedsAuthentication(status.Status)) {
		if err = b.authenticate(ctx, a.Principal(), binding, intent, data.Policy, progress); err != nil {
			return winservice.Completion{}, err
		}
	}
	return winservice.Completion{Revision: binding.Revision + 1}, nil
}
func (b *fixedLifecycleBackend) channels(ctx context.Context, v winservice.VerifiedPrincipal, binding winservice.Binding, desired p.DesiredChannels, progress func(winservice.Progress)) (winservice.Completion, error) {
	r, err := currentServiceReference(binding)
	if err != nil {
		return winservice.Completion{}, backendFailure("NO_ACTIVE_RUN")
	}
	status, err := b.status(ctx, binding)
	if err != nil {
		return winservice.Completion{}, err
	}
	if status.Status.DesiredChannels == nil {
		return winservice.Completion{}, backendFailure("UNKNOWN_CHANNEL_INTENT")
	}
	intent := *status.Status.DesiredChannels
	intent.Company = desired.Company
	intent.Personal = desired.Personal
	progress(winservice.Progress{Phase: "applying_channels"})
	var applied engine.ServiceStatusResult
	if err = b.invoke(ctx, winservice.SetChannelsLifecycle, ServiceRunPayload{ServiceRunReference: r, Channels: &intent}, &applied); err != nil {
		return winservice.Completion{}, err
	}
	status, err = b.awaitApplied(ctx, binding, intent)
	if err != nil {
		return winservice.Completion{}, err
	}
	if intent.Company && engine.NeedsAuthentication(status.Status) {
		b.mu.Lock()
		cfg, digest := b.running, b.frozenDigest
		b.mu.Unlock()
		if digest == "" {
			return winservice.Completion{}, backendFailure("AUTH_RESTART_REQUIRED")
		}
		data, err := b.userSnapshot(ctx, v, binding)
		if err != nil {
			return winservice.Completion{}, err
		}
		defer clearUserSession(&data)
		if data.EffectiveDigest != digest {
			return winservice.Completion{}, backendFailure("STOP_REQUIRED")
		}
		if err = b.authenticate(ctx, v, binding, intent, cfg, progress); err != nil {
			return winservice.Completion{}, err
		}
	}
	return winservice.Completion{Revision: binding.Revision + 1}, nil
}
func (b *fixedLifecycleBackend) authenticate(ctx context.Context, v winservice.VerifiedPrincipal, binding winservice.Binding, intent policy.ChannelIntent, cfg policy.Config, progress func(winservice.Progress)) (resultErr error) {
	if b.deps.startAuth == nil {
		return backendFailure("AUTH_NETWORK_AUTHORIZATION_REQUIRED")
	}
	status, err := b.status(ctx, binding)
	if err != nil || status.AuthNetwork == nil || !status.IPv6Blocked || !sameAppliedIntent(status.Status, intent) {
		return backendFailure("AUTH_NETWORK_AUTHORIZATION_REQUIRED")
	}
	network := winservice.UserAuthNetworkBinding{GUID: status.AuthNetwork.GUID, LUID: status.AuthNetwork.LUID, Index: status.AuthNetwork.Index, Address: status.AuthNetwork.Address, Gateway: status.AuthNetwork.Gateway, Generation: status.AuthNetwork.Generation}
	if network.Validate() != nil {
		return backendFailure("AUTH_NETWORK_AUTHORIZATION_REQUIRED")
	}
	authCtx, cancelAuth := context.WithCancel(ctx)
	defer cancelAuth()
	conversation, err := b.deps.startAuth(authCtx, v, binding, network)
	if err != nil {
		return backendFailure("AUTH_WORKER_UNAVAILABLE")
	}
	b.mu.Lock()
	if b.barrierClosedLocked() || b.conversation != nil {
		b.mu.Unlock()
		conversation.Close()
		return backendFailure("AUTH_ALREADY_PENDING")
	}
	b.conversation = conversation
	b.authGeneration = network.Generation
	b.mu.Unlock()
	// The worker verifies the physical identity around every socket. The
	// service independently invalidates its network generation while a form
	// is waiting, so a reused interface cannot retain a stale authorization.
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-authCtx.Done():
				return
			case <-ticker.C:
				checkCtx, stop := context.WithTimeout(authCtx, 5*time.Second)
				fresh, readErr := b.status(checkCtx, binding)
				stop()
				if readErr != nil || fresh.AuthNetwork == nil || fresh.AuthNetwork.Generation != network.Generation || !fresh.IPv6Blocked {
					cancelAuth()
					return
				}
			}
		}
	}()
	defer func() {
		closeErr := conversation.Close()
		b.mu.Lock()
		if b.conversation == conversation {
			b.conversation = nil
			b.authGeneration = ""
			b.challenge = nil
		}
		b.mu.Unlock()
		if resultErr == nil && closeErr != nil {
			resultErr = backendFailure("AUTH_WORKER_EXIT_UNCONFIRMED")
		}
	}()
	for {
		event, err := conversation.ReadEvent(authCtx)
		if err != nil {
			return backendFailure("AUTHENTICATION_INCOMPLETE")
		}
		switch event.Kind {
		case "challenge":
			b.mu.Lock()
			b.challenge = &p.Challenge{ID: event.ChallengeID, Kind: event.ChallengeKind, Sequence: event.Sequence, Fields: event.ChallengeFields, Expires: event.Expires}
			b.mu.Unlock()
			progress(winservice.Progress{Phase: "authentication_wait"})
		case "failed":
			return backendFailure("AUTHENTICATION_FAILED")
		case "complete":
			var session auth.Session
			if decodeServiceHelperJSON(event.Session, &session) != nil || session.Validate(cfg.VPN) != nil || !session.ValidAt(b.deps.now()) {
				clear(event.Session)
				return backendFailure("INVALID_AUTH_SESSION")
			}
			clear(event.Session)
			defer func() { session.Cookie = "" }()
			if err = conversation.Close(); err != nil {
				return backendFailure("AUTH_WORKER_EXIT_UNCONFIRMED")
			}
			if authCtx.Err() != nil {
				return backendFailure("AUTH_NETWORK_AUTHORIZATION_REQUIRED")
			}
			fresh, readErr := b.status(authCtx, binding)
			if readErr != nil || fresh.AuthNetwork == nil || fresh.AuthNetwork.Generation != network.Generation || !fresh.IPv6Blocked {
				return backendFailure("AUTH_NETWORK_AUTHORIZATION_REQUIRED")
			}
			binding, err = b.current(binding)
			if err != nil {
				return err
			}
			r, err := currentServiceReference(binding)
			if err != nil {
				return err
			}
			var applied engine.ServiceStatusResult
			if err = b.invoke(authCtx, winservice.SetChannelsLifecycle, ServiceRunPayload{ServiceRunReference: r, Channels: &intent, Auth: &session}, &applied); err != nil {
				return err
			}
			_, err = b.awaitApplied(authCtx, binding, intent)
			return err
		default:
			return backendFailure("INVALID_AUTH_EVENT")
		}
	}
}
func (b *fixedLifecycleBackend) Auth(ctx context.Context, a winservice.AuthorizedOperation, _ func(winservice.Progress)) (winservice.Completion, error) {
	if _, err := b.current(a.Binding()); err != nil {
		return winservice.Completion{}, err
	}
	b.mu.Lock()
	if b.barrierClosedLocked() {
		b.mu.Unlock()
		return winservice.Completion{}, backendFailure("STOP_BARRIER")
	}
	conversation, challenge, generation := b.conversation, b.challenge, b.authGeneration
	b.mu.Unlock()
	if conversation == nil || challenge == nil {
		return winservice.Completion{}, backendFailure("NO_AUTH_CHALLENGE")
	}
	mutation := a.Mutation()
	if mutation.Kind == p.AuthCancel {
		if mutation.CancelAuth.ChallengeID != challenge.ID {
			return winservice.Completion{}, backendFailure("CHALLENGE_CONFLICT")
		}
		return winservice.Completion{}, conversation.Close()
	}
	if mutation.Kind != p.AuthRespond || mutation.Auth.ChallengeID != challenge.ID || mutation.Auth.Sequence != challenge.Sequence {
		return winservice.Completion{}, backendFailure("CHALLENGE_CONFLICT")
	}
	status, err := b.status(ctx, a.Binding())
	if err != nil || status.AuthNetwork == nil || generation == "" || status.AuthNetwork.Generation != generation || !status.IPv6Blocked {
		conversation.Close()
		return winservice.Completion{}, backendFailure("AUTH_NETWORK_AUTHORIZATION_REQUIRED")
	}
	return winservice.Completion{}, conversation.Respond(ctx, *mutation.Auth)
}
func (b *fixedLifecycleBackend) Workspace(ctx context.Context, v winservice.VerifiedPrincipal, binding winservice.Binding, payload p.WorkspacePayload, progress func(winservice.Progress)) (winservice.Completion, error) {
	current, err := b.current(binding)
	if err != nil {
		return winservice.Completion{}, err
	}
	if current.RunRef != "" {
		return winservice.Completion{}, backendFailure("STOP_REQUIRED")
	}
	b.mu.Lock()
	if b.barrierClosedLocked() {
		b.mu.Unlock()
		return winservice.Completion{}, backendFailure("STOP_BARRIER")
	}
	b.workers++
	b.mu.Unlock()
	defer func() { b.mu.Lock(); b.workers--; b.mu.Unlock() }()
	progress(winservice.Progress{Phase: "saving_workspace"})
	output, err := b.deps.workspace(ctx, v, current, payload)
	defer clear(output)
	if err != nil {
		return winservice.Completion{}, backendFailure("WORKSPACE_OPERATION_FAILED")
	}
	var response struct {
		Completed bool            `json:"completed"`
		Result    json.RawMessage `json:"result"`
	}
	if decodeServiceHelperJSON(output, &response) != nil || !response.Completed {
		return winservice.Completion{}, backendFailure("WORKSPACE_RESULT_UNCONFIRMED")
	}
	return winservice.Completion{Revision: current.Revision + 1}, nil
}
func (b *fixedLifecycleBackend) applySettings(ctx context.Context, v winservice.VerifiedPrincipal, binding winservice.Binding, settings p.SettingsPayload, progress func(winservice.Progress)) (winservice.Completion, error) {
	if settings.AutoConnect {
		return winservice.Completion{}, backendFailure("AUTOCONNECT_UNAVAILABLE")
	}
	data, err := b.userSnapshot(ctx, v, binding)
	if err != nil {
		return winservice.Completion{}, err
	}
	defer clearUserSession(&data)
	definitionsSame := reflect.DeepEqual(policyOverrides(settings.OfficeOverrides), normalizePolicyOverrides(data.SavedPolicy.OfficeOverrides)) && reflect.DeepEqual(policyOverrides(settings.HomeOverrides), normalizePolicyOverrides(data.SavedPolicy.HomeOverrides))
	if binding.RunRef != "" {
		b.mu.Lock()
		frozen := b.frozenDigest
		b.mu.Unlock()
		if !definitionsSame || frozen == "" || frozen != data.EffectiveDigest {
			return winservice.Completion{}, backendFailure("STOP_REQUIRED")
		}
		status, err := b.status(ctx, binding)
		if err != nil {
			return winservice.Completion{}, err
		}
		if status.Status.DesiredChannels == nil {
			return winservice.Completion{}, backendFailure("UNKNOWN_CHANNEL_INTENT")
		}
		intent := *status.Status.DesiredChannels
		intent.Environment = settings.Environment
		r, err := currentServiceReference(binding)
		if err != nil {
			return winservice.Completion{}, err
		}
		var applied engine.ServiceStatusResult
		if err = b.invoke(ctx, winservice.SetChannelsLifecycle, ServiceRunPayload{ServiceRunReference: r, Channels: &intent}, &applied); err != nil {
			return winservice.Completion{}, err
		}
		if _, err = b.awaitApplied(ctx, binding, intent); err != nil {
			return winservice.Completion{}, err
		}
	} else if !definitionsSame {
		cfg := data.SavedPolicy
		cfg.OfficeOverrides = policyOverrides(settings.OfficeOverrides)
		cfg.HomeOverrides = policyOverrides(settings.HomeOverrides)
		raw, _ := json.Marshal(cfg)
		defer clear(raw)
		if _, err = b.Workspace(ctx, v, binding, p.WorkspacePayload{Action: "apply", PolicyJSON: raw, ExpectedPolicyRevision: data.PolicyRevision}, progress); err != nil {
			return winservice.Completion{}, err
		}
	}
	if err = b.deps.prefs.Save(settings); err != nil {
		return winservice.Completion{}, backendFailure("SETTINGS_PERSISTENCE_FAILED")
	}
	b.mu.Lock()
	b.settings = settings
	b.mu.Unlock()
	return winservice.Completion{Revision: binding.Revision + 1}, nil
}
func normalizePolicyOverrides(values []policy.Override) []policy.Override {
	if values == nil {
		return []policy.Override{}
	}
	return values
}
func completeRecoveryProof(proof engine.ServiceRecoveryProof) bool {
	return proof.Clean && proof.IdentityMappingComplete && proof.AdaptersAbsent && proof.ProcessesGone && proof.NetworkRestored && proof.WFPAbsent && proof.IPv6Absent && len(proof.Errors) == 0 && !proof.StartedAt.IsZero() && !proof.FinishedAt.Before(proof.StartedAt)
}
func (b *fixedLifecycleBackend) StopAndRestore(ctx context.Context, a winservice.AuthorizedOperation, progress func(winservice.Progress)) (winservice.Completion, error) {
	binding, err := b.current(a.Binding())
	if err != nil {
		return winservice.Completion{}, err
	}
	return b.restoreOwned(ctx, binding, progress)
}
func (b *fixedLifecycleBackend) restoreOwned(ctx context.Context, binding winservice.Binding, progress func(winservice.Progress)) (completion winservice.Completion, err error) {
	b.mu.Lock()
	b.exiting = true
	b.stopGeneration++
	generation := b.stopGeneration
	conversation := b.conversation
	b.conversation = nil
	b.authGeneration = ""
	b.challenge = nil
	b.mu.Unlock()
	// Reopen ordinary user work only after the complete recovery proof and all
	// old workers succeeded. A newer barrier, enrollment transfer or SCM seal
	// cannot be undone by a late completion from this restoration.
	defer func() {
		if err != nil || !completion.Restored {
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.stopGeneration == generation && !b.sealed && !b.enrollmentBarrier && !b.enrollmentFailure && b.workers == 0 && b.conversation == nil {
			b.exiting = false
		}
	}()
	var workerErr error
	if conversation != nil && conversation.Close() != nil {
		workerErr = backendFailure("AUTH_WORKER_EXIT_UNCONFIRMED")
	}
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		b.mu.Lock()
		workers := b.workers
		b.mu.Unlock()
		if workers == 0 {
			break
		}
		select {
		case <-stopCtx.Done():
			workerErr = backendFailure("USER_WORKER_EXIT_UNCONFIRMED")
			goto settled
		case <-time.After(20 * time.Millisecond):
		}
	}
settled:
	binding, err = b.current(binding)
	if err != nil {
		return winservice.Completion{}, err
	}
	if binding.RunRef == "" {
		if workerErr != nil {
			return winservice.Completion{}, workerErr
		}
		if binding.LastRestorationID != "" {
			if b.deps.restorations == nil {
				return winservice.Completion{}, backendFailure("RESTORE_PROOF_INCOMPLETE")
			}
			clean, readErr := b.deps.restorations.Verify(binding)
			if readErr != nil || !clean {
				return winservice.Completion{}, backendFailure("RESTORE_PROOF_INCOMPLETE")
			}
			return winservice.Completion{Restored: true, Revision: binding.Revision + 1, RestorationID: binding.LastRestorationID}, nil
		}
		clean, err := b.deps.pristine(binding)
		if err != nil || !clean {
			return winservice.Completion{}, backendFailure("EMPTY_STATE_PROOF_UNAVAILABLE")
		}
		now := b.deps.now()
		proof, _ := json.Marshal(map[string]any{"clean": true, "pristine": true, "never_served": true, "identity_census_complete": true, "started_at": now, "finished_at": now, "errors": []string{}})
		return b.restoredCompletion(binding, "pristine", proof)
	}
	if binding.PreparedRunID == "" && binding.SpecDigest == "" {
		var result struct {
			RunRef string          `json:"run_ref"`
			Clean  bool            `json:"clean"`
			Proof  json.RawMessage `json:"proof"`
			Error  string          `json:"error,omitempty"`
		}
		payload := struct {
			ProfileID       string `json:"profile_id"`
			RunRef          string `json:"binding_run_ref"`
			ServiceInstance string `json:"service_instance"`
		}{binding.ProfileID, binding.RunRef, binding.ServiceInstance}
		if err = b.invoke(ctx, winservice.AbortPrepareLifecycle, payload, &result); err != nil {
			return winservice.Completion{}, err
		}
		if result.RunRef != binding.RunRef || !result.Clean || result.Error != "" || !completePreparationAbort(result.Proof) {
			return winservice.Completion{}, backendFailure("RESTORE_PROOF_INCOMPLETE")
		}
		if workerErr != nil {
			return winservice.Completion{}, workerErr
		}
		return b.restoredCompletion(binding, "unprepared", result.Proof)
	}
	r, err := currentServiceReference(binding)
	if err != nil {
		return winservice.Completion{}, backendFailure("PREPARED_IDENTITY_UNAVAILABLE")
	}
	progress(winservice.Progress{Phase: "restoring"})
	recoveryCtx, recoveryCancel := context.WithTimeout(ctx, 60*time.Second)
	defer recoveryCancel()
	var result struct {
		RunID string                      `json:"run_id"`
		Clean bool                        `json:"clean"`
		Proof engine.ServiceRecoveryProof `json:"proof"`
		Error string                      `json:"error,omitempty"`
	}
	if err = b.invoke(recoveryCtx, winservice.RecoverLifecycle, ServiceRunPayload{ServiceRunReference: r}, &result); err != nil {
		return winservice.Completion{}, err
	}
	if result.RunID != r.RunID || !result.Clean || result.Error != "" || !completeRecoveryProof(result.Proof) {
		return winservice.Completion{}, backendFailure("RESTORE_PROOF_INCOMPLETE")
	}
	if workerErr != nil {
		return winservice.Completion{}, workerErr
	}
	b.mu.Lock()
	b.running = policy.Config{}
	b.frozenDigest = ""
	b.mu.Unlock()
	proof, _ := json.Marshal(result.Proof)
	return b.restoredCompletion(binding, "run", proof)
}
func (b *fixedLifecycleBackend) restoredCompletion(binding winservice.Binding, scope string, proof json.RawMessage) (winservice.Completion, error) {
	if b.deps.restorations == nil {
		return winservice.Completion{}, backendFailure("RESTORE_PROOF_INCOMPLETE")
	}
	id, err := b.deps.restorations.Save(binding, scope, proof)
	if err != nil {
		return winservice.Completion{}, backendFailure("RESTORE_PROOF_INCOMPLETE")
	}
	return winservice.Completion{Restored: true, Revision: binding.Revision + 1, RestorationID: id}, nil
}
func completePreparationAbort(data json.RawMessage) bool {
	var proof struct {
		Clean                  bool      `json:"clean"`
		NeverBound             bool      `json:"never_bound"`
		IdentityCensusComplete bool      `json:"identity_census_complete"`
		NeverServed            bool      `json:"never_served"`
		PreparedOnly           bool      `json:"prepared_only"`
		Retained               []string  `json:"retained_run_ids"`
		Errors                 []string  `json:"errors"`
		Started                time.Time `json:"started_at"`
		Finished               time.Time `json:"finished_at"`
	}
	return decodeServiceHelperJSON(data, &proof) == nil && proof.Clean && proof.NeverBound && proof.IdentityCensusComplete && proof.NeverServed && proof.PreparedOnly && len(proof.Errors) == 0 && !proof.Started.IsZero() && !proof.Finished.Before(proof.Started)
}
func (b *fixedLifecycleBackend) BeginEnrollmentBarrier(_ context.Context, _ winservice.Binding) error {
	b.mu.Lock()
	b.enrollmentBarrier = true
	b.exiting = true
	b.stopGeneration++
	conversation := b.conversation
	b.challenge = nil
	b.mu.Unlock()
	if conversation != nil {
		if err := conversation.Close(); err != nil {
			return err
		}
	}
	return nil
}
func (b *fixedLifecycleBackend) EnrollmentRotated(_ context.Context, binding winservice.Binding) error {
	b.mu.Lock()
	b.enrollmentFailure = true
	b.mu.Unlock()
	prefs, err := winservice.OpenClientSettingsStore(binding)
	if err != nil {
		return err
	}
	settings, err := prefs.Load()
	if err != nil {
		return err
	}
	restorations, err := winservice.OpenRestorationStore(binding)
	if err != nil {
		return err
	}
	return b.finishEnrollmentRotation(prefs, restorations, settings)
}
func (b *fixedLifecycleBackend) finishEnrollmentRotation(prefs servicePreferences, restorations serviceRestorations, settings p.SettingsPayload) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.workers != 0 || b.conversation != nil {
		return backendFailure("STOP_BARRIER")
	}
	b.deps.prefs = prefs
	b.deps.restorations = restorations
	b.settings = settings
	b.saved = policy.Config{}
	b.running = policy.Config{}
	b.frozenDigest = ""
	b.challenge = nil
	b.conversation = nil
	b.authGeneration = ""
	// SYSTEM may finish an already-restored pending publication during SCM
	// shutdown. Refresh its stores, but never reopen that permanently sealed host.
	b.exiting = b.sealed
	b.enrollmentBarrier = false
	b.enrollmentFailure = false
	return nil
}

var _ winservice.Backend = (*fixedLifecycleBackend)(nil)
