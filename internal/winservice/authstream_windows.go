//go:build windows

package winservice

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/windows"
	"netlaunch/internal/platform"
	p "netlaunch/internal/serviceprotocol"
)

type authRead struct {
	event UserAuthEvent
	err   error
}
type UserAuthentication struct {
	command   *exec.Cmd
	in        io.WriteCloser
	out       io.ReadCloser
	events    chan authRead
	closing   chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	writeMu   sync.Mutex
	current   UserAuthEvent
	sequence  uint64
	job       *ownedWorkerJob
}

// StartUserAuthentication uses only the pinned user worker, its fixed entry
// and a captured caller token. The context must be the service operation's
// lifetime, never an RPC read/ACK deadline.
func (e *FixedExecutor) StartUserAuthentication(ctx context.Context, principal VerifiedPrincipal, binding Binding, network UserAuthNetworkBinding) (*UserAuthentication, error) {
	if network.Validate() != nil {
		return nil, errors.New("verified authentication physical plan unavailable")
	}
	if !principal.Verified() || principal.token == 0 || authorize(principal, binding, "S-1-5-18", binding.ServiceInstance) != nil || !p.ValidID(binding.ServiceInstance) || !ValidProfileID(binding.ProfileID) {
		return nil, errors.New("verified private authentication identity required")
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
	command, err := fixedCommand(ctx, path, "--auth-worker", primary)
	if err != nil {
		return nil, err
	}
	command.Stderr = io.Discard
	command.WaitDelay = 5 * time.Second
	in, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := command.StdoutPipe()
	if err != nil {
		in.Close()
		return nil, err
	}
	if err = command.Start(); err != nil {
		in.Close()
		out.Close()
		return nil, errors.New("fixed private authentication worker unavailable")
	}
	job, err := ownWorker(command.Process.Pid)
	if err != nil {
		in.Close()
		out.Close()
		command.Process.Kill()
		command.Wait()
		return nil, errors.New("authentication worker ownership unavailable")
	}
	conversation := &UserAuthentication{command: command, in: in, out: out, events: make(chan authRead, 8), closing: make(chan struct{}), done: make(chan struct{}), job: job}
	go conversation.read()
	initial, _ := json.Marshal(struct {
		ProfileID string                 `json:"profile_id"`
		Physical  UserAuthNetworkBinding `json:"physical"`
	}{binding.ProfileID, network})
	if _, err = in.Write(append(initial, '\n')); err != nil {
		conversation.Close()
		return nil, errors.New("private authentication handshake failed")
	}
	return conversation, nil
}

func (c *UserAuthentication) read() {
	defer close(c.done)
	defer close(c.events)
	defer c.out.Close()
	defer c.job.Close()
	scanner := bufio.NewScanner(c.out)
	scanner.Buffer(make([]byte, 4096), p.MaxFrame+1)
	var terminal error
	for scanner.Scan() {
		var event UserAuthEvent
		if !utf8.Valid(scanner.Bytes()) || decodeState(scanner.Bytes(), &event) != nil || event.Validate() != nil {
			terminal = errors.New("invalid private authentication event")
			break
		}
		if err := c.acceptEvent(event); err != nil {
			terminal = err
			break
		}
		select {
		case c.events <- authRead{event: event}:
		case <-c.closing:
			terminal = context.Canceled
		}
		if terminal != nil {
			break
		}
	}
	if scanner.Err() != nil {
		terminal = errors.New("private authentication stream failed")
	}
	if terminal != nil {
		_ = c.command.Process.Kill()
	}
	if err := c.command.Wait(); err != nil && terminal == nil {
		terminal = errors.New("private authentication worker failed")
	}
	if terminal == nil {
		terminal = io.EOF
	}
	select {
	case c.events <- authRead{err: terminal}:
	case <-c.closing:
	}
}

func (c *UserAuthentication) acceptEvent(event UserAuthEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if event.Kind == "challenge" {
		if event.Sequence <= c.sequence || c.current.Kind == "challenge" {
			return errors.New("private challenge sequence did not increase")
		}
		c.sequence, c.current = event.Sequence, event
	} else {
		c.current = UserAuthEvent{}
	}
	return nil
}

// A read timeout detaches this read only; it does not stop the worker.
func (c *UserAuthentication) ReadEvent(ctx context.Context) (UserAuthEvent, error) {
	select {
	case result, ok := <-c.events:
		if !ok {
			return UserAuthEvent{}, io.EOF
		}
		return result.event, result.err
	case <-ctx.Done():
		return UserAuthEvent{}, ctx.Err()
	}
}
func (c *UserAuthentication) Respond(ctx context.Context, response UserAuthResponse) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	event := c.current
	if validateAuthResponse(event, response, time.Now()) != nil {
		c.mu.Unlock()
		return errors.New("private authentication response rejected")
	}
	data, err := json.Marshal(response)
	if err != nil || len(data) > p.MaxFrame {
		c.mu.Unlock()
		return errors.New("private authentication response limit")
	}
	// Consume this exact form before the worker can observe its answer. A fast
	// native worker may emit the next challenge before the pipe write returns.
	// A failed write closes the owned conversation rather than reusing the form.
	c.current = UserAuthEvent{}
	c.mu.Unlock()
	finished := make(chan error, 1)
	go func() { _, err := c.in.Write(append(data, '\n')); finished <- err }()
	select {
	case err = <-finished:
		if err != nil {
			c.Close()
			return errors.New("private authentication response failed")
		}
		return nil
	case <-ctx.Done():
		// Cancellation here is stop/service cancellation of accepted work.
		// Closing exact owned pipes prevents any late credential write.
		c.Close()
		return ctx.Err()
	case <-c.closing:
		return context.Canceled
	}
}
func (c *UserAuthentication) Cancel() error { return c.Close() }
func (c *UserAuthentication) Identity() platform.Identity {
	if c.job == nil {
		return platform.Identity{}
	}
	return c.job.identity
}
func (c *UserAuthentication) Close() error {
	c.closeOnce.Do(func() {
		close(c.closing)
		_ = c.in.Close()
		_ = c.out.Close()
		if c.job != nil {
			_ = c.job.Close()
		}
		if c.command.Process != nil {
			err := c.command.Process.Kill()
			if errors.Is(err, os.ErrProcessDone) {
				err = nil
			}
			_ = err
		}
	})
	select {
	case <-c.done:
		if c.job != nil {
			return c.job.Close()
		}
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("private authentication worker exit not confirmed")
	}
}
