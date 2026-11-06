//go:build windows

package winservice

import (
	"context"
	"errors"
	"golang.org/x/sys/windows/svc"
	"os"
	"strings"
	"time"
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

type serviceHandler struct {
	factory      func() (*Host, error)
	validate     func(*Host) error
	serve        func(context.Context, *Host) error
	restore      func(context.Context, *Host) error
	ticks        <-chan time.Time
	initExpired  <-chan time.Time
	recoveryOnly bool
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
		host *Host
		err  error
	}
	preparedCh := make(chan prepared, 1)
	go func() {
		if h.factory == nil {
			preparedCh <- prepared{err: errors.New("BACKEND_UNAVAILABLE")}
			return
		}
		host, err := h.factory()
		if err == nil {
			err = validate(host)
		}
		preparedCh <- prepared{host, err}
	}()
	var host *Host
	stopping := false
	initializing := true
	for initializing {
		select {
		case result := <-preparedCh:
			if result.err != nil {
				return false, 1
			}
			host = result.host
			initializing = false
		case <-expired:
			return false, 1
		case <-ticks:
			current.CheckPoint++
			status <- current
		case request, ok := <-requests:
			if !ok {
				return false, 1
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
				return false, 1
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
					return false, 1
				}
				if h.recoveryOnly && writeRecoveryAcknowledgement(host, args) != nil {
					return false, 1
				}
				return false, 0
			case <-restoreCtx.Done():
				cancel()
				return false, 1
			case <-ticks:
				current.CheckPoint++
				status <- current
			case request, ok := <-requests:
				if !ok {
					cancel()
					return false, 1
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
