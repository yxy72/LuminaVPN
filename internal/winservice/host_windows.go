//go:build windows

package winservice

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	p "netlaunch/internal/serviceprotocol"
)

type Host struct {
	Broker       *Broker
	ServiceSID   string
	LogonSID     string
	Installation Installation
}

func (h *Host) Validate() error {
	if h == nil || h.Broker == nil || !h.Installation.Ready() || !sidText.MatchString(h.ServiceSID) || !sidText.MatchString(h.LogonSID) {
		return errors.New("BACKEND_UNAVAILABLE")
	}
	path, err := h.Installation.Executable(ServiceImage)
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil || !strings.EqualFold(self, path) {
		return errors.New("service host is not the protected installed release")
	}
	return nil
}
func RunConfiguredService(factory func() (*Host, error)) error {
	if factory == nil {
		return errors.New("BACKEND_UNAVAILABLE")
	}
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		return errors.New("SCM service context required; this entry never installs or elevates")
	}
	// Enter the dispatcher before protected release hashing or state reads.
	// Initialization belongs to START_PENDING, with SCM checkpoints.
	return svc.Run(ServiceName, &serviceHandler{factory: factory})
}
func RunConfiguredRecoveryService(factory func() (*Host, error)) error {
	if factory == nil {
		return errors.New("BACKEND_UNAVAILABLE")
	}
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		return errors.New("SCM recovery context required")
	}
	return svc.Run(RecoveryServiceName, &serviceHandler{factory: factory, recoveryOnly: true})
}

// These service-specific SCM exit codes contain only fixed stages. Windows
// records them even when the service exits before it can write protected state.
const (
	recoveryExitFactory              uint32 = 201
	recoveryExitValidation           uint32 = 202
	recoveryExitInitializationTimed  uint32 = 203
	recoveryExitControlsClosed       uint32 = 204
	recoveryExitRestore              uint32 = 205
	recoveryExitRestoreTimed         uint32 = 206
	recoveryExitAcknowledgement      uint32 = 207
	recoveryExitOwnership            uint32 = 211
	recoveryExitAccess               uint32 = 212
	recoveryExitEnrollment           uint32 = 213
	recoveryExitHelper               uint32 = 214
	recoveryExitHelperResponse       uint32 = 215
	recoveryExitProof                uint32 = 216
	recoveryExitEmptyStateProof      uint32 = 217
	recoveryExitPreparedIdentity     uint32 = 218
	recoveryExitAuthenticationWorker uint32 = 219
	recoveryExitUserWorker           uint32 = 220
)

func recoveryServiceExitStage(code uint32) string {
	switch code {
	case recoveryExitFactory:
		return "host_factory"
	case recoveryExitValidation:
		return "host_validation"
	case recoveryExitInitializationTimed:
		return "initialization_timeout"
	case recoveryExitControlsClosed:
		return "controls_closed"
	case recoveryExitRestore:
		return "restoration"
	case recoveryExitRestoreTimed:
		return "restoration_timeout"
	case recoveryExitAcknowledgement:
		return "acknowledgement"
	case recoveryExitOwnership:
		return "restoration_ownership"
	case recoveryExitAccess:
		return "restoration_access"
	case recoveryExitEnrollment:
		return "restoration_enrollment"
	case recoveryExitHelper:
		return "restoration_helper"
	case recoveryExitHelperResponse:
		return "restoration_helper_response"
	case recoveryExitProof:
		return "restoration_proof"
	case recoveryExitEmptyStateProof:
		return "restoration_empty_state_proof"
	case recoveryExitPreparedIdentity:
		return "restoration_prepared_identity"
	case recoveryExitAuthenticationWorker:
		return "restoration_authentication_worker"
	case recoveryExitUserWorker:
		return "restoration_user_worker"
	default:
		return "unknown"
	}
}

func recoveryRestoreExitCode(err error) uint32 {
	if errors.Is(err, context.DeadlineExceeded) {
		return recoveryExitRestoreTimed
	}
	var failure *p.Error
	if !errors.As(err, &failure) || failure == nil {
		return recoveryExitRestore
	}
	switch failure.Code {
	case "OWNERSHIP_UNAVAILABLE":
		return recoveryExitOwnership
	case "ACCESS_DENIED":
		return recoveryExitAccess
	case "ENROLLMENT_PERSISTENCE_FAILED":
		return recoveryExitEnrollment
	case "FIXED_HELPER_FAILED":
		return recoveryExitHelper
	case "INVALID_HELPER_RESPONSE":
		return recoveryExitHelperResponse
	case "RESTORE_INCOMPLETE", "RESTORE_PROOF_INCOMPLETE":
		return recoveryExitProof
	case "EMPTY_STATE_PROOF_UNAVAILABLE":
		return recoveryExitEmptyStateProof
	case "PREPARED_IDENTITY_UNAVAILABLE":
		return recoveryExitPreparedIdentity
	case "AUTH_WORKER_EXIT_UNCONFIRMED":
		return recoveryExitAuthenticationWorker
	case "USER_WORKER_EXIT_UNCONFIRMED":
		return recoveryExitUserWorker
	default:
		return recoveryExitRestore
	}
}

type serviceHandler struct {
	factory      func() (*Host, error)
	validate     func(*Host) error
	serve        func(context.Context, *Host) error
	restore      func(context.Context, *Host) error
	ticks        <-chan time.Time
	initExpired  <-chan time.Time
	recoveryOnly bool
}

func (h *serviceHandler) failure(recoveryCode uint32) (bool, uint32) {
	if h.recoveryOnly {
		return true, recoveryCode
	}
	return false, 1
}

func (h *serviceHandler) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	current := svc.Status{State: svc.StartPending, CheckPoint: 1, WaitHint: 30000}
	status <- current
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := h.ticks
	if ticks == nil {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		ticks = ticker.C
	}
	expired := h.initExpired
	if expired == nil {
		timer := time.NewTimer(2 * time.Minute)
		defer timer.Stop()
		expired = timer.C
	}
	validate := h.validate
	if validate == nil {
		validate = func(host *Host) error { return host.Validate() }
	}
	serve := h.serve
	if serve == nil {
		serve = func(ctx context.Context, host *Host) error {
			return host.Broker.ServePipe(ctx, host.ServiceSID, host.LogonSID)
		}
	}
	restore := h.restore
	if restore == nil {
		restore = func(ctx context.Context, host *Host) error { return host.Broker.Shutdown(ctx) }
	}
	type prepared struct {
		host        *Host
		failureCode uint32
	}
	preparedCh := make(chan prepared, 1)
	go func() {
		if h.factory == nil {
			preparedCh <- prepared{failureCode: recoveryExitFactory}
			return
		}
		host, err := h.factory()
		if err != nil {
			preparedCh <- prepared{failureCode: recoveryExitFactory}
			return
		}
		if err = validate(host); err != nil {
			preparedCh <- prepared{failureCode: recoveryExitValidation}
			return
		}
		preparedCh <- prepared{host: host}
	}()
	var host *Host
	stopping := false
	initializing := true
	for initializing {
		select {
		case result := <-preparedCh:
			if result.failureCode != 0 {
				return h.failure(result.failureCode)
			}
			host = result.host
			initializing = false
		case <-expired:
			return h.failure(recoveryExitInitializationTimed)
		case <-ticks:
			current.CheckPoint++
			status <- current
		case request, ok := <-requests:
			if !ok {
				return h.failure(recoveryExitControlsClosed)
			}
			switch request.Cmd {
			case svc.Stop, svc.Shutdown:
				stopping = true
				current.State = svc.StopPending
				current.CheckPoint++
				current.WaitHint = 30000
				status <- current
			case svc.Interrogate:
				status <- current
			}
		}
	}
	// Process a stop already queued during the final validation step before
	// publishing RUNNING or opening a control-plane connection.
	for drain := true; drain; {
		select {
		case request, ok := <-requests:
			if !ok {
				return h.failure(recoveryExitControlsClosed)
			}
			if request.Cmd == svc.Stop || request.Cmd == svc.Shutdown {
				stopping = true
			}
		default:
			drain = false
		}
	}
	finish := func() (bool, uint32) {
		current = svc.Status{State: svc.StopPending, CheckPoint: 1, WaitHint: 60000}
		status <- current
		restoreCtx, stop := context.WithTimeout(context.Background(), 60*time.Second)
		defer stop()
		restored := make(chan error, 1)
		go func() { restored <- restore(restoreCtx, host) }()
		for {
			select {
			case err := <-restored:
				cancel()
				if err != nil {
					if h.recoveryOnly {
						return true, recoveryRestoreExitCode(err)
					}
					return false, 1
				}
				if h.recoveryOnly && writeRecoveryAcknowledgement(host, args) != nil {
					return h.failure(recoveryExitAcknowledgement)
				}
				return false, 0
			case <-restoreCtx.Done():
				cancel()
				return h.failure(recoveryExitRestoreTimed)
			case <-ticks:
				current.CheckPoint++
				status <- current
			case request, ok := <-requests:
				if !ok {
					cancel()
					return h.failure(recoveryExitControlsClosed)
				}
				if request.Cmd == svc.Interrogate {
					status <- current
				}
			}
		}
	}
	if stopping || h.recoveryOnly {
		return finish()
	}
	errorsCh := make(chan error, 1)
	go func() { errorsCh <- serve(ctx, host) }()
	current = svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	status <- current
	for {
		select {
		case err := <-errorsCh:
			if err != nil {
				_, _ = finish()
				return false, 1
			}
			return false, 0
		case request, ok := <-requests:
			if !ok {
				return finish()
			}
			switch request.Cmd {
			case svc.Interrogate:
				status <- current
			case svc.Stop, svc.Shutdown:
				return finish()
			}
		}
	}
}
