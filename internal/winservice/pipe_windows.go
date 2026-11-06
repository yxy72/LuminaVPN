//go:build windows

package winservice

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	p "netlaunch/internal/serviceprotocol"
)

var impersonatePipe = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")
var getServerPID = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetNamedPipeServerProcessId")

type pipeIO struct {
	handle   windows.Handle
	ctx      context.Context
	owned    bool
	once     sync.Once
	deadline time.Time
}

func (c *pipeIO) SetDeadline(at time.Time) error { c.deadline = at; return nil }

type windowsPending struct {
	handle windows.Handle
	ov     *windows.Overlapped
	done   *uint32
	event  windows.Handle
}

func (w windowsPending) Wait() (bool, error) {
	status, err := windows.WaitForSingleObject(w.event, 50)
	return status == windows.WAIT_OBJECT_0, err
}
func (w windowsPending) Complete() error {
	return windows.GetOverlappedResult(w.handle, w.ov, w.done, false)
}
func (w windowsPending) CancelAndDrain() error {
	cancel := windows.CancelIoEx(w.handle, w.ov)
	if cancel == windows.ERROR_NOT_FOUND {
		cancel = nil
	}
	drain := windows.GetOverlappedResult(w.handle, w.ov, w.done, true)
	if drain == windows.ERROR_OPERATION_ABORTED {
		drain = nil
	}
	return errors.Join(cancel, drain)
}

func (c *pipeIO) Close() error {
	c.once.Do(func() {
		_ = windows.CancelIoEx(c.handle, nil)
		if c.owned {
			_ = windows.CloseHandle(c.handle)
		}
	})
	return nil
}
func (c *pipeIO) transfer(data []byte, write bool) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	if !c.deadline.IsZero() && !time.Now().Before(c.deadline) {
		return 0, context.DeadlineExceeded
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	ov := windows.Overlapped{HEvent: event}
	var done uint32
	var pinned runtime.Pinner
	pinned.Pin(&ov)
	pinned.Pin(&done)
	if len(data) > 0 {
		pinned.Pin(&data[0])
	}
	defer pinned.Unpin()
	defer func() { runtime.KeepAlive(data); runtime.KeepAlive(&ov); runtime.KeepAlive(&done) }()
	if write {
		err = windows.WriteFile(c.handle, data, &done, &ov)
	} else {
		err = windows.ReadFile(c.handle, data, &done, &ov)
	}
	if err == windows.ERROR_IO_PENDING {
		err = finishPending(c.ctx, func() bool { return !c.deadline.IsZero() && !time.Now().Before(c.deadline) }, windowsPending{c.handle, &ov, &done, event})
	}
	if err == windows.ERROR_BROKEN_PIPE || err == windows.ERROR_PIPE_NOT_CONNECTED {
		return 0, io.EOF
	}
	if !c.deadline.IsZero() && !time.Now().Before(c.deadline) {
		return 0, context.DeadlineExceeded
	}
	return int(done), err
}
func (c *pipeIO) Read(data []byte) (int, error)  { return c.transfer(data, false) }
func (c *pipeIO) Write(data []byte) (int, error) { return c.transfer(data, true) }

func connectInstance(ctx context.Context, handle windows.Handle) error {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(event)
	ov := windows.Overlapped{HEvent: event}
	var pinned runtime.Pinner
	pinned.Pin(&ov)
	defer pinned.Unpin()
	defer runtime.KeepAlive(&ov)
	err = windows.ConnectNamedPipe(handle, &ov)
	if err == windows.ERROR_PIPE_CONNECTED {
		return nil
	}
	if err != windows.ERROR_IO_PENDING {
		return err
	}
	var done uint32
	pinned.Pin(&done)
	defer runtime.KeepAlive(&done)
	return finishPending(ctx, func() bool { return false }, windowsPending{handle, &ov, &done, event})
}

// ServePipe holds its first instance for the entire service lifetime, then
// creates a bounded pool in that already-owned namespace. No default SD is used.
func (b *Broker) ServePipe(ctx context.Context, serviceSID, logonSID string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 2)
	go func() { errs <- b.servePipePool(ctx, serviceSID, logonSID, PipeName, 8, false) }()
	go func() { errs <- b.servePipePool(ctx, serviceSID, logonSID, StopPipeName, 2, true) }()
	err := <-errs
	cancel()
	<-errs
	return err
}
func (b *Broker) servePipePool(ctx context.Context, serviceSID, logonSID, nameText string, count int, stopOnly bool) error {
	sddl, err := PipeSDDL(serviceSID, logonSID)
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	name, _ := windows.UTF16PtrFromString(nameText)
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	handles := make([]windows.Handle, 0, count)
	defer func() {
		for _, h := range handles {
			_ = windows.CloseHandle(h)
		}
		runtime.KeepAlive(sd)
	}()
	for i := 0; i < count; i++ {
		flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
		if i == 0 {
			flags |= PipeFirstInstance
		}
		h, e := windows.CreateNamedPipe(name, flags, PipeRejectRemote, uint32(count), p.MaxFrame, p.MaxFrame, 0, &sa)
		if e != nil {
			return e
		}
		handles = append(handles, h)
	}
	var wg sync.WaitGroup
	for _, h := range handles {
		wg.Add(1)
		go func(handle windows.Handle) {
			defer wg.Done()
			for ctx.Err() == nil {
				if connectInstance(ctx, handle) != nil {
					return
				}
				connection := &pipeIO{handle: handle, ctx: ctx}
				if stopOnly {
					_ = b.serveStopConnection(ctx, connection)
				} else {
					_ = b.ServeConnection(ctx, connection, connection, func() (VerifiedPrincipal, error) { return capturePipePrincipal(handle) })
				}
				_ = windows.DisconnectNamedPipe(handle)
			}
		}(h)
	}
	<-ctx.Done()
	for _, h := range handles {
		_ = windows.CancelIoEx(h, nil)
	}
	wg.Wait()
	return nil
}
func (b *Broker) serveStopConnection(ctx context.Context, c *pipeIO) error {
	c.SetDeadline(time.Now().Add(5 * time.Second))
	scanner := bufio.NewScanner(c)
	scanner.Buffer(make([]byte, 4096), p.MaxFrame+1)
	if !scanner.Scan() {
		return scanner.Err()
	}
	request, err := p.DecodeRequest(scanner.Bytes())
	if err != nil || request.Method != "submit" || request.Mutation == nil || !request.Mutation.PriorityStop() {
		return safeError("STOP_METHOD_REQUIRED")
	}
	peer, err := capturePipePrincipal(c.handle)
	if err != nil {
		return err
	}
	defer peer.Close()
	op, err := b.Submit(ctx, peer, *request.Mutation)
	response := p.Response{}
	if err != nil {
		response.Error = wireError(err)
	} else {
		response.Operation = &op
	}
	data, _ := json.Marshal(response)
	c.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = c.Write(append(data, '\n'))
	return err
}

type tokenStatistics struct {
	TokenID            windows.LUID
	AuthenticationID   windows.LUID
	Expiration         int64
	TokenType          uint32
	ImpersonationLevel uint32
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedID         windows.LUID
}

func tokenFacts(token windows.Token) (VerifiedPrincipal, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return VerifiedPrincipal{}, err
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return VerifiedPrincipal{}, err
	}
	var logon string
	for _, group := range groups.AllGroups() {
		if group.Attributes&0xC0000000 == 0xC0000000 {
			logon = group.Sid.String()
		}
	}
	var session uint32
	var needed uint32
	if err = windows.GetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4, &needed); err != nil {
		return VerifiedPrincipal{}, err
	}
	var stats tokenStatistics
	if err = windows.GetTokenInformation(token, windows.TokenStatistics, (*byte)(unsafe.Pointer(&stats)), uint32(unsafe.Sizeof(stats)), &needed); err != nil {
		return VerifiedPrincipal{}, err
	}
	if err = requireImpersonationToken(stats.TokenType, stats.ImpersonationLevel); err != nil {
		return VerifiedPrincipal{}, err
	}
	v := VerifiedPrincipal{sid: user.User.Sid.String(), logonSID: logon, authenticationID: fmt.Sprintf("%08x-%08x", stats.AuthenticationID.HighPart, stats.AuthenticationID.LowPart), sessionID: session, verified: true}
	if !v.Verified() || v.sid == "S-1-5-18" || v.sid == "S-1-5-7" {
		return VerifiedPrincipal{}, errors.New("interactive authenticated caller required")
	}
	epoch, interactive, epochErr := kernelLogonEpoch(stats.AuthenticationID, v.sid, session)
	if epochErr != nil {
		return VerifiedPrincipal{}, epochErr
	}
	v.logonEpoch = epoch
	profile, profileErr := token.GetUserProfileDirectory()
	if profileErr == nil && filepath.IsAbs(profile) {
		v.profileID = localProfileID(filepath.Join(profile, ".netlaunch"))
	}
	elevated, elevationErr := explicitTokenElevation(token)
	if elevationErr != nil {
		return VerifiedPrincipal{}, elevationErr
	}
	v.ordinary = interactive && !elevated && v.profileID != ""
	return v, nil
}
func principalForToken(token windows.Token) (VerifiedPrincipal, error) {
	v, err := tokenFacts(token)
	if err != nil {
		return v, err
	}
	var once sync.Once
	v.release = func() { once.Do(func() { _ = token.Close() }) }
	v.token = uintptr(token)
	v.impersonate = func(fn func() error) error { return withToken(token, fn) }
	v.retain = func() (VerifiedPrincipal, error) {
		var duplicate windows.Token
		if err := windows.DuplicateTokenEx(token, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &duplicate); err != nil {
			return VerifiedPrincipal{}, err
		}
		value, err := principalForToken(duplicate)
		if err != nil {
			duplicate.Close()
		}
		return value, err
	}
	return v, nil
}
func withToken(token windows.Token, fn func() error) error {
	finished := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := windows.SetThreadToken(nil, token); err != nil {
			runtime.UnlockOSThread()
			finished <- err
			return
		}
		var result error
		func() {
			defer func() {
				if recover() != nil {
					result = errors.New("caller operation panicked")
				}
			}()
			result = fn()
		}()
		if err := windows.RevertToSelf(); err != nil {
			finished <- errors.New("caller impersonation could not be reverted")
			runtime.Goexit()
		}
		runtime.UnlockOSThread()
		finished <- result
	}()
	return <-finished
}
func capturePipePrincipal(handle windows.Handle) (VerifiedPrincipal, error) {
	type answer struct {
		peer VerifiedPrincipal
		err  error
	}
	result := make(chan answer, 1)
	go func() {
		runtime.LockOSThread()
		ok, _, callErr := impersonatePipe.Call(uintptr(handle))
		if ok == 0 {
			runtime.UnlockOSThread()
			result <- answer{err: errors.New("named pipe caller impersonation failed")}
			_ = callErr
			return
		}
		var token windows.Token
		err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_IMPERSONATE, true, &token)
		var duplicate windows.Token
		if err == nil {
			// Check the original last-message token before duplicating it; a
			// readable identification token must not become execution authority.
			_, err = tokenFacts(token)
			if err == nil {
				err = windows.DuplicateTokenEx(token, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &duplicate)
			}
			_ = token.Close()
		}
		if revert := windows.RevertToSelf(); revert != nil {
			if duplicate != 0 {
				duplicate.Close()
			}
			result <- answer{err: errors.New("named pipe caller could not be reverted")}
			runtime.Goexit()
		}
		runtime.UnlockOSThread()
		if err != nil {
			result <- answer{err: err}
			return
		}
		peer, err := principalForToken(duplicate)
		if err != nil {
			duplicate.Close()
		}
		result <- answer{peer: peer, err: err}
	}()
	value := <-result
	return value.peer, value.err
}

type pipeClient struct {
	mu             sync.Mutex
	attachRequests map[string]string
}

func NewClient() p.Client { return &pipeClient{attachRequests: map[string]string{}} }
func (c *pipeClient) call(ctx context.Context, request p.Request) (p.Response, error) {
	var response p.Response
	installation, err := LoadInstallation()
	if err != nil {
		return response, safeError("SERVICE_UNAVAILABLE")
	}
	nameText := PipeName
	if request.Mutation != nil && request.Mutation.PriorityStop() {
		nameText = StopPipeName
	}
	name, _ := windows.UTF16PtrFromString(nameText)
	handle, err := windows.CreateFile(name, PipeClientRights, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IMPERSONATION, 0)
	if err != nil {
		return response, safeError("SERVICE_UNAVAILABLE")
	}
	connection := &pipeIO{handle: handle, ctx: ctx, owned: true}
	if deadline, ok := ctx.Deadline(); ok {
		connection.SetDeadline(deadline)
	} else {
		connection.SetDeadline(time.Now().Add(5 * time.Second))
	}
	defer connection.Close()
	if err = verifyPipeServer(handle, installation); err != nil {
		return response, safeError("SERVICE_IDENTITY_REJECTED")
	}
	data, err := json.Marshal(request)
	if err != nil || len(data) > p.MaxFrame {
		return response, safeError("INVALID_REQUEST")
	}
	if _, err = connection.Write(append(data, '\n')); err != nil {
		return response, safeError("SERVICE_UNAVAILABLE")
	}
	scanner := bufio.NewScanner(connection)
	scanner.Buffer(make([]byte, 4096), p.MaxFrame+1)
	if !scanner.Scan() {
		return response, safeError("SERVICE_UNAVAILABLE")
	}
	if err = json.Unmarshal(scanner.Bytes(), &response); err != nil {
		return response, safeError("INVALID_RESPONSE")
	}
	if response.Error != nil {
		return response, response.Error
	}
	return response, nil
}
func (c *pipeClient) Snapshot(ctx context.Context, profile string) (p.Snapshot, error) {
	response, err := c.call(ctx, p.Request{Version: p.Version, Method: "snapshot", ProfileID: profile})
	if err != nil {
		var denied *p.Error
		if errors.As(err, &denied) && denied.Code == "ACCESS_DENIED" {
			c.mu.Lock()
			requestID := c.attachRequests[profile]
			if requestID == "" {
				requestID, _ = newID("attach-")
				if c.attachRequests == nil {
					c.attachRequests = map[string]string{}
				}
				c.attachRequests[profile] = requestID
			}
			c.mu.Unlock()
			attachment, attachErr := c.Submit(ctx, p.Mutation{RequestID: requestID, ProfileID: profile, Kind: p.AttachEnrollment, Attach: &p.AttachPayload{}})
			if attachErr == nil && attachment.Kind == p.AttachEnrollment {
				if attachment.Completed && attachment.Error == nil {
					if attached, readErr := c.call(ctx, p.Request{Version: p.Version, Method: "snapshot", ProfileID: profile}); readErr == nil && attached.Snapshot != nil {
						return discardRemoteExitProof(*attached.Snapshot), nil
					}
				}
				state := "attaching"
				if attachment.Error != nil {
					state = "unavailable"
				}
				return p.Snapshot{ProtocolVersion: p.Version, ServiceState: state, TakeoverState: "restoring", ProfileID: profile, Revision: attachment.Revision, OperationID: attachment.ID, RecoveryRequired: true, Company: p.Channel{State: "unknown", Route: "unknown", IPv6: "unknown"}, Personal: p.Channel{State: "unknown", Route: "unknown", IPv6: "unknown"}}, nil
			}
			var already *p.Error
			if errors.As(attachErr, &already) && already.Code == "ALREADY_ATTACHED" {
				if attached, readErr := c.call(ctx, p.Request{Version: p.Version, Method: "snapshot", ProfileID: profile}); readErr == nil && attached.Snapshot != nil {
					return discardRemoteExitProof(*attached.Snapshot), nil
				}
			}
			if attachErr != nil {
				err = attachErr
			}
		}
		if local, proven := localAbsentSnapshot(profile); proven {
			return local, nil
		}
		return p.Snapshot{ProtocolVersion: p.Version, ProfileID: profile, ServiceState: "unavailable", TakeoverState: "unknown", RecoveryRequired: true}, err
	}
	if response.Snapshot == nil {
		return p.Snapshot{}, safeError("INVALID_RESPONSE")
	}
	return discardRemoteExitProof(*response.Snapshot), nil
}
func (c *pipeClient) Submit(ctx context.Context, m p.Mutation) (p.Operation, error) {
	if m.Validate() != nil {
		return p.Operation{}, safeError("INVALID_REQUEST")
	}
	response, err := c.call(ctx, p.Request{Version: p.Version, Method: "submit", Mutation: &m})
	if err != nil {
		return p.Operation{}, err
	}
	if response.Operation == nil {
		return p.Operation{}, safeError("INVALID_RESPONSE")
	}
	return *response.Operation, nil
}
func (c *pipeClient) Operation(ctx context.Context, id string) (p.Operation, error) {
	response, err := c.call(ctx, p.Request{Version: p.Version, Method: "operation", OperationID: id})
	if err != nil {
		return p.Operation{}, err
	}
	if response.Operation == nil {
		return p.Operation{}, safeError("INVALID_RESPONSE")
	}
	return *response.Operation, nil
}
func verifyPipeServer(handle windows.Handle, installation Installation) error {
	var pid uint32
	ok, _, _ := getServerPID.Call(uintptr(handle), uintptr(unsafe.Pointer(&pid)))
	if ok == 0 || pid == 0 {
		return errors.New("pipe server identity unavailable")
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err = windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user.User.Sid.String() != "S-1-5-18" {
		return errors.New("pipe server is not service executor")
	}
	serviceSID, _, _, err := windows.LookupSID("", "NT SERVICE\\"+ServiceName)
	if err != nil {
		return err
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return err
	}
	found := false
	for _, g := range groups.AllGroups() {
		found = found || (g.Sid.Equals(serviceSID) && g.Attributes&windows.SE_GROUP_ENABLED != 0)
	}
	if !found {
		return errors.New("pipe server service SID missing")
	}
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err = windows.QueryFullProcessImageName(process, 0, &buf[0], &size); err != nil {
		return err
	}
	expected, err := installation.Executable(ServiceImage)
	if err != nil || !strings.EqualFold(filepath.Clean(windows.UTF16ToString(buf[:size])), expected) {
		return errors.New("pipe server image differs from protected release")
	}
	return nil
}

type WindowsProtectedFiles struct{ Root string }

func (fs WindowsProtectedFiles) ReadProtected(path string) ([]byte, error) {
	if err := fs.validatePath(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if len(data) > 256<<20 {
		return nil, errors.New("installed file too large")
	}
	return data, err
}
func (fs WindowsProtectedFiles) validatePath(path string) error {
	root := filepath.Clean(fs.Root)
	relative, err := filepath.Rel(root, path)
	if !filepath.IsAbs(root) || !filepath.IsAbs(path) || filepath.Clean(path) != path || err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return errors.New("path leaves installed root")
	}
	if err := checkProtectedACL(filepath.Dir(root)); err != nil {
		return err
	}
	for ancestor := filepath.Dir(root); ; ancestor = filepath.Dir(ancestor) {
		name, parseErr := windows.UTF16PtrFromString(ancestor)
		if parseErr != nil {
			return parseErr
		}
		attributes, attrErr := windows.GetFileAttributes(name)
		if attrErr != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("installed ancestor is reparse or unverified")
		}
		if err := checkACLMask(ancestor, ancestorReplaceMask); err != nil {
			return err
		}
		if filepath.Dir(ancestor) == ancestor {
			break
		}
	}
	for current := path; ; current = filepath.Dir(current) {
		_, err := os.Lstat(current)
		if err != nil {
			return err
		}
		name, parseErr := windows.UTF16PtrFromString(current)
		if parseErr != nil {
			return parseErr
		}
		attrs, attrErr := windows.GetFileAttributes(name)
		if attrErr != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("installed path is reparse or unverified")
		}
		if err = checkProtectedACL(current); err != nil {
			return err
		}
		if strings.EqualFold(current, root) {
			break
		}
		if filepath.Dir(current) == current {
			return errors.New("installed root mismatch")
		}
	}
	return nil
}
func checkProtectedACL(path string) error {
	return checkACLMask(path, protectedWriteMask)
}
func checkACLMask(path string, mask uint32) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil {
		return errors.New("installed object has no trusted owner")
	}
	ownerText := owner.String()
	ownerTrusted := ownerText == "S-1-5-18" || ownerText == "S-1-5-32-544"
	installer, _, _, lookupErr := windows.LookupSID("", "NT SERVICE\\TrustedInstaller")
	additional := map[string]bool{}
	if lookupErr == nil {
		additional[installer.String()] = true
		ownerTrusted = ownerTrusted || owner.Equals(installer)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("installed object has no explicit DACL")
	}
	entries := []protectedACE{}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var raw *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(acl, i, &raw); err != nil {
			return err
		}
		entry := protectedACE{Kind: raw.Header.AceType, Flags: raw.Header.AceFlags, Mask: uint32(raw.Mask)}
		if entry.Kind == 0 {
			entry.SID = (*windows.SID)(unsafe.Pointer(&raw.SidStart)).String()
		}
		entries = append(entries, entry)
	}
	runtime.KeepAlive(sd)
	return validateDescriptorWriters(ownerTrusted, entries, mask, additional)
}
func LoadInstallation() (Installation, error) {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return Installation{}, err
	}
	root := filepath.Join(programFiles, "LuminaVPN")
	fs := WindowsProtectedFiles{Root: root}
	data, err := fs.ReadProtected(filepath.Join(root, "release-catalog.json"))
	if err != nil {
		return Installation{}, err
	}
	var catalog ReleaseCatalog
	if len(data) > p.MaxFrame || json.Unmarshal(data, &catalog) != nil {
		return Installation{}, errors.New("invalid protected release catalog")
	}
	return ValidateInstallation(root, catalog, fs)
}
