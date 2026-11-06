// Package desktopbridge implements the ordinary-permission desktop protocol.
// The default protocol remains read-only. The explicit Windows client build
// adds bounded service requests; the bridge never owns a network lifecycle.
package desktopbridge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"netlaunch/internal/app"
	"netlaunch/internal/application"
)

const MaxFrame = 1 << 20
const ProtocolMajor = 1

var Methods = []string{"session.hello", "state.get", "profile.inspect", "nodes.list", "config.get", "subscriptions.summary", "environment.check", "recovery.describe"}

type Request struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}
type RPCError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}
type Response struct {
	ID     string    `json:"id"`
	Result any       `json:"result,omitempty"`
	Error  *RPCError `json:"error,omitempty"`
}
type Server struct {
	Service    *application.Desktop
	AppVersion string
	session    string
	hello      bool
}

func strict(data []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	var rest any
	if err := decoder.Decode(&rest); err != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

func decodeParams(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' {
		return errors.New("parameters must be an object")
	}
	return strict(raw, v)
}

func protocolError(code, message string) *RPCError { return &RPCError{Code: code, Message: message} }

func (s *Server) respond(ctx context.Context, r Request) Response {
	response := Response{ID: r.ID}
	if r.ID == "" || len(r.ID) > 128 || r.Method == "" {
		response.Error = protocolError("INVALID_REQUEST", "Request id and method are required.")
		return response
	}
	if r.Method == "session.hello" {
		var p struct {
			ProtocolMajor int    `json:"protocol_major"`
			AppVersion    string `json:"app_version"`
		}
		if decodeParams(r.Params, &p) != nil || (p.ProtocolMajor != 0 && p.ProtocolMajor != ProtocolMajor) || len(p.AppVersion) > 128 {
			response.Error = protocolError("PROTOCOL_MISMATCH", "Unsupported desktop protocol or handshake.")
			return response
		}
		if s.session == "" {
			var token [16]byte
			if _, err := rand.Read(token[:]); err != nil {
				response.Error = protocolError("SESSION_UNAVAILABLE", "Desktop session unavailable.")
				return response
			}
			s.session = hex.EncodeToString(token[:])
		}
		s.hello = true
		build := app.DesktopBuild()
		methods := append([]string{}, Methods...)
		client := s.Service.ClientEnabled()
		if client {
			methods = append(methods, application.ClientMethods...)
		}
		response.Result = map[string]any{"protocol_major": ProtocolMajor, "session_id": s.session, "build": build.Info, "mode": build.Mode, "capabilities": map[string]any{"read_only": !client, "connection_start": client, "connection_stop": client, "config_write": client, "windows_client": client, "validation_only": client && build.Capabilities.ValidationOnly, "validation_maximum_seconds": build.Capabilities.ValidationMaximumSeconds, "requires_installed_service": client, "native_lifecycle": build.Capabilities.NativeLifecycle, "methods": methods}}
		return response
	}
	if !s.hello {
		response.Error = protocolError("HANDSHAKE_REQUIRED", "Read the desktop handshake before requesting state.")
		return response
	}
	var result any
	var err error
	if application.IsClientMethod(r.Method) {
		result, err = s.Service.ClientRequest(ctx, r.Method, r.Params)
	} else if r.Method == "nodes.list" || r.Method == "config.get" {
		var p struct {
			Offset int  `json:"offset"`
			Limit  *int `json:"limit"`
		}
		maxOffset := 256
		if r.Method == "config.get" {
			maxOffset = 50000
		}
		if decodeParams(r.Params, &p) != nil || p.Offset < 0 || p.Offset > maxOffset || p.Limit != nil && (*p.Limit < 1 || *p.Limit > 100) {
			response.Error = protocolError("INVALID_PARAMS", "Pagination offset must be within the inventory bounds; limit is 1–100.")
			return response
		}
		limit := 100
		if p.Limit != nil {
			limit = *p.Limit
		}
		if r.Method == "nodes.list" {
			result, err = s.Service.ListNodes(p.Offset, limit)
		} else {
			result, err = s.Service.Config(p.Offset, limit)
		}
	} else {
		if decodeParams(r.Params, &struct{}{}) != nil {
			response.Error = protocolError("INVALID_PARAMS", "This read method accepts no parameters.")
			return response
		}
		switch r.Method {
		case "state.get":
			result = s.Service.GetState()
		case "profile.inspect":
			result = s.Service.InspectProfile()
		case "subscriptions.summary":
			result, err = s.Service.Subscriptions()
		case "environment.check":
			result, err = s.Service.Environment(ctx)
		case "recovery.describe":
			result = s.Service.Recovery()
		default:
			response.Error = protocolError("METHOD_NOT_FOUND", "This method is not available in the read-only desktop preview.")
			return response
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		var safe *application.Error
		switch {
		case errors.As(err, &safe):
			response.Error = &RPCError{safe.Code, safe.Message, safe.Retryable}
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
			response.Error = &RPCError{"READ_TIMEOUT", "The read did not finish within its time budget.", true}
		default:
			response.Error = protocolError("READ_FAILED", "The local read could not be completed; private details omitted.")
		}
	} else {
		response.Result = result
	}
	return response
}

func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	// One active request stays below the protocol maximum of sixteen. A submit
	// only awaits the service's durable acknowledgement, never its worker lifetime.
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), MaxFrame+1)
	write := func(response Response) error {
		raw, err := json.Marshal(response)
		if err != nil {
			return err
		}
		if len(raw) > MaxFrame {
			raw, _ = json.Marshal(Response{ID: response.ID, Error: protocolError("RESPONSE_TOO_LARGE", "Read result exceeds the protocol frame limit.")})
		}
		_, err = out.Write(append(raw, '\n'))
		return err
	}
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil
		}
		frame := scanner.Bytes()
		response := Response{}
		if len(frame) > MaxFrame {
			response.Error = protocolError("FRAME_TOO_LARGE", "Request frame exceeds one MiB.")
		} else if !utf8.Valid(frame) {
			response.Error = protocolError("INVALID_REQUEST", "Request must contain UTF-8 JSON.")
		} else {
			var request Request
			if strict(frame, &request) != nil {
				response.Error = protocolError("INVALID_REQUEST", "Request does not match the desktop protocol.")
			} else {
				readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				response = s.respond(readCtx, request)
				cancel()
			}
		}
		// A disconnected UI cannot authorize additional actions. Already accepted
		// service operations continue independently; EOF/EPIPE ends this proxy.
		if err := write(response); err != nil {
			return nil
		}
	}
	if scanner.Err() != nil {
		_ = write(Response{Error: protocolError("FRAME_TOO_LARGE", "Request frame could not be read within the protocol limit.")})
	}
	return nil
}

func Run(args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 || args[0] != "serve" {
		return errors.New("desktop requires serve")
	}
	flags := flag.NewFlagSet("desktop serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	profile := flags.String("profile", "", "fixed private local profile directory")
	bundle := flags.String("runtime", "", "fixed bundled runtime directory")
	version := flags.String("app-version", "", "public desktop build version")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || len(*version) > 128 {
		return errors.New("invalid desktop launch arguments")
	}
	if *bundle == "" {
		executable, err := os.Executable()
		if err != nil {
			return errors.New("bundled runtime location unavailable")
		}
		*bundle = filepath.Join(filepath.Dir(executable), "runtime")
	}
	service, err := application.NewDesktop(*profile, *bundle)
	if err != nil {
		return err
	}
	ignoreBrokenPipe()
	return (&Server{Service: service, AppVersion: *version}).Serve(context.Background(), in, out)
}
