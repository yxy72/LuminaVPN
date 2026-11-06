//go:build windows

package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
	"netlaunch/internal/auth"
	"netlaunch/internal/policy"
	"netlaunch/internal/securefile"
	p "netlaunch/internal/serviceprotocol"
	"netlaunch/internal/winservice"
)

type serviceAuthEngine interface {
	Authenticate(context.Context, policy.VPN, func([]p.AuthField) ([]p.AuthFieldValue, error)) (auth.Session, error)
}
type serviceAuthDependencies struct {
	identity func() error
	profile  func() (string, error)
	policy   func(string) (policy.Config, error)
	engine   func(winservice.UserAuthNetworkBinding) (serviceAuthEngine, error)
	save     func(string, policy.VPN, auth.Session) error
	now      func() time.Time
	network  winservice.UserAuthNetworkBinding
}

// ServiceUserAuthenticate is a service-owned private conversation. It loads a
// reviewed DLL in this fixed user worker; it never opens a console, passes
// credentials in argv, runs a script or interprets text prompts from stdout.
func ServiceUserAuthenticate(in io.Reader, out io.Writer) error {
	return serviceUserAuthenticate(in, out, serviceAuthDependencies{identity: serviceInteractiveUser, profile: DefaultProfile, policy: DesktopWorkspacePolicy, engine: newInstalledAuthEngine, save: auth.Save, now: time.Now})
}
func serviceUserAuthenticate(in io.Reader, out io.Writer, deps serviceAuthDependencies) error {
	if deps.identity() != nil {
		return errors.New("interactive user identity unavailable")
	}
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), p.MaxFrame+1)
	if !scanner.Scan() {
		return errors.New("private authentication handshake unavailable")
	}
	var request struct {
		ProfileID string                            `json:"profile_id"`
		Physical  winservice.UserAuthNetworkBinding `json:"physical"`
	}
	if privateAuthDecode(scanner.Bytes(), &request) != nil || request.Physical.Validate() != nil {
		return errors.New("invalid private authentication handshake")
	}
	profile, err := serviceDefaultProfile(request.ProfileID, deps.profile)
	if err != nil {
		return err
	}
	cfg, err := deps.policy(profile)
	if err != nil || cfg.ValidateForStorage() != nil || cfg.VPN.Server == "" || cfg.VPN.EndpointIPv4 == "" {
		return errors.New("configured VPN authentication target unavailable")
	}
	unlock, err := securefile.Lock(filepath.Join(profile, "auth.lock"), time.Second)
	if err != nil {
		return errors.New("another authentication owns this profile")
	}
	defer unlock()
	deps.network = request.Physical
	return authenticatePrivateStream(scanner, out, profile, cfg, deps)
}
func privateAuthDecode(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > p.MaxFrame || !utf8.Valid(raw) {
		return errors.New("invalid private authentication frame")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid typed private authentication frame")
	}
	return nil
}
func authenticatePrivateStream(scanner *bufio.Scanner, out io.Writer, profile string, cfg policy.Config, deps serviceAuthDependencies) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	replies := make(chan p.AuthPayload, 1)
	go func() {
		defer close(replies)
		for scanner.Scan() {
			var response p.AuthPayload
			if privateAuthDecode(scanner.Bytes(), &response) != nil || response.Validate() != nil {
				cancel()
				return
			}
			select {
			case replies <- response:
			case <-ctx.Done():
				return
			}
		}
		cancel()
	}()
	engine, err := deps.engine(deps.network)
	if err != nil {
		return errors.New("reviewed structured authentication engine unavailable")
	}
	var sequence uint64
	prompt := func(fields []p.AuthField) ([]p.AuthFieldValue, error) {
		if sequence >= 32 || len(fields) == 0 || len(fields) > 16 {
			return nil, errors.New("unsupported native authentication form")
		}
		sequence++
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return nil, errors.New("challenge identity unavailable")
		}
		expires := deps.now().Add(2 * time.Minute)
		if deadline, ok := ctx.Deadline(); ok && expires.After(deadline) {
			expires = deadline
		}
		event := winservice.UserAuthEvent{Version: 1, Kind: "challenge", ChallengeID: "auth-" + hex.EncodeToString(nonce), Sequence: sequence, ChallengeKind: "form", ChallengeFields: fields, Expires: expires}
		if event.Validate() != nil || writeServicePrivateFrame(out, event) != nil {
			return nil, errors.New("private authentication challenge unavailable")
		}
		timer := time.NewTimer(time.Until(expires))
		defer timer.Stop()
		select {
		case response, ok := <-replies:
			if !ok || response.ChallengeID != event.ChallengeID || response.Sequence != event.Sequence || !deps.now().Before(expires) || response.Username+response.Password+response.OTP != "" || len(response.Fields) != len(fields) {
				return nil, errors.New("response does not match live native form")
			}
			values := map[string]string{}
			for _, field := range response.Fields {
				values[field.FieldID] = field.Value
			}
			for _, field := range fields {
				value, ok := values[field.FieldID]
				if !ok {
					return nil, errors.New("native form field missing")
				}
				if field.Kind == "select" {
					found := false
					for _, choice := range field.Choices {
						found = found || choice.ChoiceID == value
					}
					if !found {
						return nil, errors.New("native form choice unknown")
					}
				}
			}
			return response.Fields, nil
		case <-timer.C:
			return nil, errors.New("native authentication challenge expired")
		case <-ctx.Done():
			return nil, errors.New("private authentication cancelled")
		}
	}
	session, err := engine.Authenticate(ctx, cfg.VPN, prompt)
	if err != nil || ctx.Err() != nil || session.Validate(cfg.VPN) != nil || !session.ValidAt(deps.now()) {
		_ = writeServicePrivateFrame(out, winservice.UserAuthEvent{Version: 1, Kind: "failed", Code: "AUTH_REJECTED"})
		return errors.New("structured authentication did not complete")
	}
	// Save only a validated session, under the actual user's DPAPI context.
	if deps.save(profile, cfg.VPN, session) != nil {
		return errors.New("user session cache unavailable")
	}
	if ctx.Err() != nil {
		return errors.New("private authentication cancelled before completion")
	}
	encoded, err := json.Marshal(session)
	if err != nil || len(encoded) > 64<<10 {
		return errors.New("private authenticated session exceeds limit")
	}
	defer clear(encoded)
	defer func() { session.Cookie = "" }()
	return writeServicePrivateFrame(out, winservice.UserAuthEvent{Version: 1, Kind: "complete", Session: encoded})
}

// Layouts are the public API-5 structures at upstream commit 70d1e79,
// openconnect.h. Windows amd64 uses 8-byte pointers and 32-bit C int/unsigned.
// No private header fields or server-authored pointers survive a callback.
type ocOption struct {
	Next               uintptr
	Type               int32
	_                  uint32
	Name, Label, Value uintptr
	Flags              uint32
	_pad               uint32
	Reserved           uintptr
}
type ocSelect struct {
	Option  ocOption
	Count   int32
	_       uint32
	Choices uintptr
}
type ocChoice struct{ Name, Label, AuthType, OverrideName, OverrideLabel uintptr }
type ocForm struct {
	Banner, Message, Error, AuthID, Method, Action, Options, AuthGroup uintptr
	AuthGroupSelection                                                 int32
	_                                                                  uint32
}
type nativeField struct {
	pointer    uintptr
	choices    map[string]string
	groupIndex map[string]int32
}

func nativeText(pointer uintptr, max int) (string, error) {
	if pointer == 0 {
		return "", nil
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(pointer)), max+1)
	for index, value := range data {
		if value == 0 {
			if !utf8.Valid(data[:index]) {
				break
			}
			return string(data[:index]), nil
		}
	}
	return "", errors.New("native authentication string exceeds bound")
}
func nativeFormFields(pointer uintptr) ([]p.AuthField, map[string]nativeField, error) {
	if pointer == 0 || unsafe.Sizeof(ocOption{}) != 56 || unsafe.Sizeof(ocSelect{}) != 72 || unsafe.Sizeof(ocForm{}) != 72 {
		return nil, nil, errors.New("unsupported native authentication ABI")
	}
	form := (*ocForm)(unsafe.Pointer(pointer))
	fields := []p.AuthField{}
	bindings := map[string]nativeField{}
	seen := map[uintptr]bool{}
	for current := form.Options; current != 0; {
		if seen[current] || len(seen) >= 64 {
			return nil, nil, errors.New("invalid native authentication option chain")
		}
		seen[current] = true
		option := (*ocOption)(unsafe.Pointer(current))
		next := option.Next
		if option.Flags&1 != 0 || option.Type == 4 {
			current = next
			continue
		}
		if len(fields) >= 16 {
			return nil, nil, errors.New("native authentication field limit")
		}
		id := fmt.Sprintf("f%d", len(fields))
		field := p.AuthField{FieldID: id}
		binding := nativeField{pointer: current}
		switch option.Type {
		case 1:
			name, err := nativeText(option.Name, 128)
			if err != nil {
				return nil, nil, err
			}
			if name != "username" && name != "user" {
				return nil, nil, errors.New("unreviewed native text field")
			}
			field.Kind, field.LabelCode = "username", "ACCOUNT"
		case 2:
			label, err := nativeText(option.Label, 128)
			if err != nil {
				return nil, nil, err
			}
			switch strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(label), ":"))) {
			case "password", "密码":
				field.LabelCode = "SECRET"
			case "secondary password", "second password":
				field.LabelCode = "SECOND_SECRET"
			case "passcode":
				field.LabelCode = "PASSCODE"
			case "otp", "token", "one-time password", "动态码":
				field.LabelCode = "OTP"
			default:
				return nil, nil, errors.New("unreviewed native password prompt")
			}
			field.Kind = "password"
		case 5:
			field.Kind, field.LabelCode = "otp", "OTP"
		case 3:
			selectOption := (*ocSelect)(unsafe.Pointer(current))
			if selectOption.Count < 1 || selectOption.Count > 64 || selectOption.Choices == 0 {
				return nil, nil, errors.New("invalid native authentication choices")
			}
			field.Kind, field.LabelCode = "select", "AUTH_GROUP"
			binding.choices = map[string]string{}
			binding.groupIndex = map[string]int32{}
			choices := unsafe.Slice((*uintptr)(unsafe.Pointer(selectOption.Choices)), int(selectOption.Count))
			for index, entry := range choices {
				if entry == 0 {
					return nil, nil, errors.New("missing native choice")
				}
				choice := (*ocChoice)(unsafe.Pointer(entry))
				name, err := nativeText(choice.Name, 256)
				if err != nil || name == "" {
					return nil, nil, errors.New("invalid native choice name")
				}
				label, err := nativeText(choice.Label, 128)
				if err != nil || strings.ContainsAny(label, "\x00\r\n") {
					return nil, nil, errors.New("invalid native choice label")
				}
				if label == "" {
					label = fmt.Sprintf("选项 %d", index+1)
				}
				choiceID := fmt.Sprintf("c%d", index)
				field.Choices = append(field.Choices, p.AuthChoice{ChoiceID: choiceID, Label: label})
				binding.choices[choiceID] = name
				binding.groupIndex[choiceID] = int32(index)
			}
		default:
			return nil, nil, errors.New("unsupported SSO or native authentication form")
		}
		fields = append(fields, field)
		bindings[id] = binding
		current = next
	}
	if len(fields) == 0 {
		return nil, nil, errors.New("empty native authentication form")
	}
	return fields, bindings, nil
}

type installedAuthEngine struct {
	root, dll, ca string
	physical      winservice.UserAuthNetworkBinding
}

func newInstalledAuthEngine(physical winservice.UserAuthNetworkBinding) (serviceAuthEngine, error) {
	if physical.Validate() != nil {
		return nil, errors.New("verified physical authentication route required")
	}
	if runtime.GOARCH != "amd64" {
		return nil, errors.New("reviewed authentication ABI requires amd64")
	}
	installed, err := winservice.LoadInstallation()
	if err != nil {
		return nil, errors.New("protected installed runtime unavailable")
	}
	root, manifest, err := installed.RuntimeManifest()
	if err != nil {
		return nil, err
	}
	found := map[string]bool{}
	for _, entry := range manifest.Files {
		if entry.Path != "bin/libopenconnect-5.dll" && entry.Path != "certs/ca-bundle.crt" {
			continue
		}
		data, err := (winservice.WindowsProtectedFiles{Root: root}).ReadProtected(filepath.Join(root, filepath.FromSlash(entry.Path)))
		if err != nil {
			return nil, errors.New("protected authentication runtime unavailable")
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != entry.SHA256 {
			return nil, errors.New("authentication runtime pin changed")
		}
		found[entry.Path] = true
	}
	if !found["bin/libopenconnect-5.dll"] || !found["certs/ca-bundle.crt"] {
		return nil, errors.New("reviewed authentication components missing")
	}
	return &installedAuthEngine{root: root, dll: filepath.Join(root, "bin", "libopenconnect-5.dll"), ca: filepath.Join(root, "certs", "ca-bundle.crt"), physical: physical}, nil
}
func (engine *installedAuthEngine) Authenticate(ctx context.Context, vpn policy.VPN, prompt func([]p.AuthField) ([]p.AuthFieldValue, error)) (auth.Session, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	guard, err := newServiceAuthSocketGuard(ctx, engine.physical, cancel)
	if err != nil {
		return auth.Session{}, errors.New("verified physical authentication binding unavailable")
	}
	handle, err := windows.LoadLibraryEx(engine.dll, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return auth.Session{}, errors.New("reviewed authentication DLL unavailable")
	}
	dll := &windows.DLL{Name: engine.dll, Handle: handle}
	defer dll.Release()
	names := []string{"openconnect_init_ssl", "openconnect_vpninfo_new", "openconnect_vpninfo_free", "openconnect_set_protocol", "openconnect_parse_url", "openconnect_set_cafile", "openconnect_set_system_trust", "openconnect_set_http_proxy", "openconnect_set_http_auth", "openconnect_set_option_value", "openconnect_obtain_cookie", "openconnect_get_cookie", "openconnect_get_peer_cert_hash", "openconnect_override_getaddrinfo", "openconnect_setup_cmd_pipe", "openconnect_set_webview_callback", "openconnect_set_external_browser_callback", "openconnect_set_protect_socket_handler"}
	procs := map[string]*windows.Proc{}
	for _, name := range names {
		proc, err := dll.FindProc(name)
		if err != nil {
			return auth.Session{}, errors.New("reviewed authentication API missing")
		}
		procs[name] = proc
	}
	call := func(name string, args ...uintptr) uintptr { result, _, _ := procs[name].Call(args...); return result }
	cString := func(value string) ([]byte, error) {
		if strings.IndexByte(value, 0) >= 0 {
			return nil, errors.New("invalid native authentication text")
		}
		return append([]byte(value), 0), nil
	}
	withString := func(name string, info uintptr, value string) error {
		buffer, err := cString(value)
		if err != nil {
			return err
		}
		defer clear(buffer)
		result := call(name, info, uintptr(unsafe.Pointer(&buffer[0])))
		runtime.KeepAlive(buffer)
		if int32(result) != 0 {
			return errors.New("native authentication configuration rejected")
		}
		return nil
	}
	if int32(call("openconnect_init_ssl")) != 0 {
		return auth.Session{}, errors.New("native TLS initialization failed")
	}
	rejectCertificate := windows.NewCallbackCDecl(func(uintptr, uintptr) uintptr { return 1 })
	ignoreConfig := windows.NewCallbackCDecl(func(uintptr, uintptr, uintptr) uintptr { return 0 })
	ignoreProgress := windows.NewCallbackCDecl(func(uintptr, uintptr, uintptr) uintptr { return 0 })
	rejectBrowser := windows.NewCallbackCDecl(func(uintptr, uintptr, uintptr) uintptr { return 1 })
	formCallback := windows.NewCallbackCDecl(func(_ uintptr, formPointer uintptr) uintptr {
		fields, bindings, err := nativeFormFields(formPointer)
		if err != nil {
			return 1
		}
		values, err := prompt(fields)
		if err != nil {
			return 1
		}
		form := (*ocForm)(unsafe.Pointer(formPointer))
		newGroup := false
		for _, value := range values {
			binding, ok := bindings[value.FieldID]
			if !ok {
				return 1
			}
			text := value.Value
			if binding.choices != nil {
				var exists bool
				text, exists = binding.choices[text]
				if !exists {
					return 1
				}
				if binding.pointer == form.AuthGroup {
					selected := binding.groupIndex[value.Value]
					newGroup = selected != form.AuthGroupSelection
					form.AuthGroupSelection = selected
				}
			}
			if withString("openconnect_set_option_value", binding.pointer, text) != nil {
				return 1
			}
		}
		for index := range values {
			values[index].Value = ""
		}
		if newGroup {
			return 2
		}
		return 0
	})
	userAgent := append([]byte("LuminaVPN"), 0)
	info := call("openconnect_vpninfo_new", uintptr(unsafe.Pointer(&userAgent[0])), rejectCertificate, ignoreConfig, formCallback, ignoreProgress, 0)
	runtime.KeepAlive(userAgent)
	if info == 0 {
		return auth.Session{}, errors.New("native authentication context unavailable")
	}
	callbacks := []uintptr{rejectCertificate, ignoreConfig, formCallback, ignoreProgress, rejectBrowser}
	defer func() {
		call("openconnect_vpninfo_free", info)
		runtime.KeepAlive(callbacks)
	}()
	call("openconnect_set_system_trust", info, 0)
	call("openconnect_set_http_proxy", info, 0)
	call("openconnect_set_webview_callback", info, rejectBrowser)
	call("openconnect_set_external_browser_callback", info, rejectBrowser)
	for _, setting := range []struct{ name, value string }{{"openconnect_set_protocol", "anyconnect"}, {"openconnect_set_cafile", engine.ca}, {"openconnect_set_http_auth", "Basic"}, {"openconnect_parse_url", vpn.Server}} {
		if withString(setting.name, info, setting.value) != nil {
			return auth.Session{}, errors.New("native authentication setup rejected")
		}
	}
	target, err := url.Parse(vpn.Server)
	if err != nil {
		return auth.Session{}, errors.New("invalid authentication target")
	}
	resolver := windows.NewLazySystemDLL("ws2_32.dll").NewProc("getaddrinfo")
	resolveCallback := windows.NewCallbackCDecl(func(_ uintptr, node, service, hints, result uintptr) uintptr {
		requested, err := nativeText(node, 253)
		if err != nil || !strings.EqualFold(requested, target.Hostname()) {
			return uintptr(uint32(11001))
		}
		endpoint := append([]byte(vpn.EndpointIPv4), 0)
		value, _, _ := resolver.Call(uintptr(unsafe.Pointer(&endpoint[0])), service, hints, result)
		runtime.KeepAlive(endpoint)
		return value
	})
	call("openconnect_override_getaddrinfo", info, resolveCallback)
	callbacks = append(callbacks, resolveCallback)
	protectCallback := windows.NewCallbackCDecl(func(_ uintptr, raw uintptr) uintptr { guard.Protect(raw); return 0 })
	call("openconnect_set_protect_socket_handler", info, protectCallback)
	callbacks = append(callbacks, protectCallback)
	socket := call("openconnect_setup_cmd_pipe", info)
	if socket == ^uintptr(0) {
		return auth.Session{}, errors.New("native authentication cancellation unavailable")
	}
	stopped, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			command := []byte{'x'}
			_, _, _ = windows.NewLazySystemDLL("ws2_32.dll").NewProc("send").Call(socket, uintptr(unsafe.Pointer(&command[0])), 1, 0)
			runtime.KeepAlive(command)
		case <-done:
		}
	}()
	defer func() { close(done); <-stopped }()
	if int32(call("openconnect_obtain_cookie", info)) != 0 || ctx.Err() != nil || guard.Err() != nil {
		return auth.Session{}, errors.New("native authentication rejected")
	}
	cookie, err := nativeText(call("openconnect_get_cookie", info), 65536)
	if err != nil {
		return auth.Session{}, err
	}
	fingerprint, err := nativeText(call("openconnect_get_peer_cert_hash", info), 512)
	if err != nil {
		return auth.Session{}, err
	}
	session := auth.Session{Cookie: cookie, Host: target.Hostname(), Fingerprint: fingerprint, Created: time.Now()}
	if session.Validate(vpn) != nil {
		return auth.Session{}, errors.New("native authenticated session invalid")
	}
	return session, nil
}
