package engine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"netlaunch/internal/buildinfo"
	"netlaunch/internal/platform"
	"netlaunch/internal/securefile"
)

const (
	darwinServiceLabel    = "com.luminavpn.network"
	darwinServiceRoot     = "/Library/PrivilegedHelperTools/" + darwinServiceLabel
	darwinServiceSocket   = darwinServiceRoot + "/service.sock"
	darwinServiceProtocol = 1
)

var errDarwinServiceUnavailable = errors.New("macOS background network service is unavailable")

type darwinServiceRequest struct {
	Version  int                           `json:"version"`
	Action   string                        `json:"action"`
	Profile  string                        `json:"profile,omitempty"`
	Run      string                        `json:"run,omitempty"`
	Company  *DarwinDesktopCompanyRequest  `json:"company,omitempty"`
	Personal *DarwinDesktopPersonalRequest `json:"personal,omitempty"`
}

type darwinServiceReply struct {
	OK    bool   `json:"ok"`
	Build string `json:"build,omitempty"`
	Run   string `json:"run,omitempty"`
}

func darwinServiceBuild() string {
	info := buildinfo.Current()
	return info.Version + "/" + info.Revision
}

func darwinProfileKey(profile string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(filepath.Clean(profile))))
}

func darwinServiceRuns(uid int, key string) string {
	return filepath.Join(darwinServiceRoot, "runs", strconv.Itoa(uid), key)
}

func darwinRunID(name string) bool {
	id, ok := strings.CutPrefix(name, "netlaunch-")
	return ok && darwinHexKey(id, 32)
}

func darwinHexKey(key string, length int) bool {
	if len(key) != length || strings.ToLower(key) != key {
		return false
	}
	_, err := hex.DecodeString(key)
	return err == nil
}

func darwinProfileKeyValid(key string) bool {
	return darwinHexKey(key, 64)
}

func darwinServiceRun(run string) (key, name string, ok bool) {
	relative, err := filepath.Rel(filepath.Join(darwinServiceRoot, "runs", strconv.Itoa(os.Getuid())), run)
	if err != nil {
		return "", "", false
	}
	key, name, ok = strings.Cut(relative, "/")
	return key, name, ok && darwinProfileKeyValid(key) && darwinRunID(name)
}

func MacServiceProfileRun(profile, run string) bool {
	key, _, ok := darwinServiceRun(run)
	return ok && key == darwinProfileKey(profile)
}

func darwinServicePeer(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *unix.Xucred
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	})
	if err != nil || sockErr != nil || cred == nil {
		return -1, errors.New("macOS service peer credentials are unavailable")
	}
	return int(cred.Uid), nil
}

func darwinServiceCall(ctx context.Context, req darwinServiceRequest) (darwinServiceReply, error) {
	var reply darwinServiceReply
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", darwinServiceSocket)
	if err != nil {
		if ctx.Err() != nil {
			return reply, ctx.Err()
		}
		return reply, errDarwinServiceUnavailable
	}
	defer conn.Close()
	uid, err := darwinServicePeer(conn.(*net.UnixConn))
	if err != nil || uid != 0 {
		return reply, errDarwinServiceUnavailable
	}
	closeOnCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer closeOnCancel()
	req.Version = darwinServiceProtocol
	if err = json.NewEncoder(conn).Encode(req); err == nil {
		err = json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&reply)
	}
	if ctx.Err() != nil {
		return reply, ctx.Err()
	}
	if err != nil {
		return reply, errDarwinServiceUnavailable
	}
	if !reply.OK {
		return reply, errors.New("macOS background network operation did not complete")
	}
	return reply, nil
}

func PrepareMacServiceRun(ctx context.Context, profile, bundle string) (string, error) {
	health, cancel := context.WithTimeout(ctx, 2*time.Second)
	reply, err := darwinServiceCall(health, darwinServiceRequest{Action: "status"})
	cancel()
	if err != nil || reply.Build != darwinServiceBuild() {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := authorizeDarwinService(ctx, bundle); err != nil {
			return "", err
		}
		ready, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		for {
			reply, err = darwinServiceCall(ready, darwinServiceRequest{Action: "status"})
			if err == nil && reply.Build == darwinServiceBuild() {
				break
			}
			select {
			case <-ready.Done():
				return "", errDarwinServiceUnavailable
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	reply, err = darwinServiceCall(ctx, darwinServiceRequest{Action: "allocate", Profile: darwinProfileKey(profile)})
	if err != nil {
		return "", err
	}
	if !darwinRunID(reply.Run) {
		return "", errDarwinServiceUnavailable
	}
	return filepath.Join(darwinServiceRuns(os.Getuid(), darwinProfileKey(profile)), reply.Run), nil
}

func DiscardMacServiceRun(ctx context.Context, run string) {
	// The desktop removes its own files first. The service only removes the empty directory.
	if key, name, ok := darwinServiceRun(run); ok {
		_, _ = darwinServiceCall(ctx, darwinServiceRequest{Action: "discard", Profile: key, Run: name})
	}
}

func requestDarwinServiceRun(ctx context.Context, run string, req darwinServiceRequest) (bool, error) {
	key, name, ok := darwinServiceRun(run)
	if !ok {
		return false, nil
	}
	req.Profile, req.Run = key, name
	_, err := darwinServiceCall(ctx, req)
	return true, err
}

// Only the authenticated desktop account may submit actions. Every path is
// derived under a root-controlled parent. The desktop can write data inside a
// run but cannot move its directory or supply the programs the service runs.
func serveDarwinDesktopService(uid int) error {
	if os.Geteuid() != 0 || uid <= 0 {
		return errors.New("system network service needs a valid desktop account")
	}
	if err := checkDarwinServiceDir(darwinServiceRoot); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	bundle := filepath.Join(filepath.Dir(self), "runtime")
	if err := checkDarwinServiceDir(bundle); err != nil {
		return err
	}
	if err := os.Remove(darwinServiceSocket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: darwinServiceSocket, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(darwinServiceSocket, 0600); err != nil {
		return err
	}
	if err = os.Chown(darwinServiceSocket, uid, -1); err != nil {
		return err
	}
	// Keep room for priority recovery even while a channel request runs.
	slots := make(chan struct{}, 16)
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			return err
		}
		peer, err := darwinServicePeer(conn)
		if err != nil || peer != uid {
			conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				dec := json.NewDecoder(io.LimitReader(conn, 4096))
				dec.DisallowUnknownFields()
				var req darwinServiceRequest
				reply := darwinServiceReply{}
				if dec.Decode(&req) == nil {
					reply = handleDarwinServiceRequest(uid, self, req)
				}
				_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
				_ = json.NewEncoder(conn).Encode(reply)
			}()
		default:
			conn.Close()
		}
	}
}

func handleDarwinServiceRequest(uid int, executable string, req darwinServiceRequest) darwinServiceReply {
	failed := darwinServiceReply{}
	if req.Version != darwinServiceProtocol {
		return failed
	}
	if req.Action == "status" && req.Profile == "" && req.Run == "" && req.Company == nil && req.Personal == nil {
		return darwinServiceReply{OK: true, Build: darwinServiceBuild()}
	}
	if !darwinProfileKeyValid(req.Profile) || (req.Action == "company") != (req.Company != nil) || (req.Action == "personal") != (req.Personal != nil) {
		return failed
	}
	parent := darwinServiceRuns(uid, req.Profile)
	if req.Action == "allocate" && req.Run == "" {
		if err := makeDarwinServiceDir(parent); err != nil {
			return failed
		}
		var id [16]byte
		rand.Read(id[:])
		run := filepath.Join(parent, "netlaunch-"+hex.EncodeToString(id[:]))
		if err := os.Mkdir(run, 0700); err != nil {
			return failed
		}
		if err := os.Chown(run, uid, -1); err != nil {
			_ = os.Remove(run)
			return failed
		}
		return darwinServiceReply{OK: true, Run: filepath.Base(run)}
	}
	if !darwinRunID(req.Run) || checkDarwinServiceDir(parent) != nil {
		return failed
	}
	run := filepath.Join(parent, req.Run)
	info, err := os.Lstat(run)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return failed
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid {
		return failed
	}
	switch req.Action {
	case "discard":
		if _, err := os.Lstat(private(run)); !errors.Is(err, os.ErrNotExist) {
			return failed
		}
		err = os.Remove(run)
	case "serve":
		err = startDarwinServiceRun(executable, run, uid)
	case "recover", "recover-verified":
		err = recoverDarwinServiceRun(run, req.Action)
	case "company":
		err = ApplyDarwinDesktopCompany(run, *req.Company)
	case "personal":
		err = ApplyDarwinDesktopPersonal(run, *req.Personal)
	default:
		return failed
	}
	return darwinServiceReply{OK: err == nil}
}

func startDarwinServiceRun(executable, run string, uid int) error {
	m, err := ReadManifest(run)
	if err != nil || m.Owner != uid || m.Mode == "" || validateDarwinRunStart(m, time.Now()) != nil {
		return errors.New("desktop run was not prepared for the network service")
	}
	if _, err := os.Lstat(filepath.Join(run, "STOP")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("desktop network start was cancelled")
	}
	cmd := exec.Command(executable, "_serve", "--run", run)
	cmd.Dir = filepath.Dir(executable)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/var/root"}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

func recoverDarwinServiceRun(run, action string) error {
	// Prevent a queued coordinator from publishing a journal between checking
	// a never-started run and writing its cancellation marker.
	if err := securefile.Dir(filepath.Dir(private(run))); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(private(run), "state.json")); errors.Is(err, os.ErrNotExist) {
		unlock, lockErr := securefile.Lock(filepath.Join(filepath.Dir(private(run)), "active.lock"), time.Second)
		_, journalErr := os.Lstat(filepath.Join(private(run), "state.json"))
		if lockErr == nil {
			if errors.Is(journalErr, os.ErrNotExist) {
				defer unlock()
				return recoverRun(run, "local_stop")
			}
			unlock()
		} else if journalErr != nil {
			return lockErr
		}
	}
	return Internal(action, run)
}

func darwinInstalledRuntime(run string) (string, error) {
	serviceRuns := filepath.Join(darwinServiceRoot, "runs") + "/"
	if !strings.HasPrefix(run, serviceRuns) {
		return filepath.Join(run, "runtime"), nil
	}
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	bundle := filepath.Join(filepath.Dir(self), "runtime")
	if !strings.HasPrefix(bundle, filepath.Join(darwinServiceRoot, "builds")+"/") {
		return "", errors.New("desktop network service executable is outside its installation")
	}
	if err := checkDarwinServiceDir(bundle); err != nil {
		return "", err
	}
	return bundle, nil
}

func validateDarwinServiceBindings(run string, m Manifest) error {
	if !strings.HasPrefix(run, filepath.Join(darwinServiceRoot, "runs")+"/") {
		return nil
	}
	vpn, tun, err := platform.Candidates()
	if err != nil || m.Network.Interface != m.Binding.Physical || vpn != m.Binding.VPN || tun != m.Binding.TUN ||
		m.Binding.ControllerPort < 1024 || m.Binding.ControllerPort > 65535 || m.Binding.ControllerPort == m.Config.Ports.Proxy || m.Binding.ControllerPort == m.Config.Ports.DNS {
		return errors.New("desktop network service requires current interface and port bindings")
	}
	return nil
}
