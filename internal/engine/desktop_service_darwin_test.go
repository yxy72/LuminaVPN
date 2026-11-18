package engine

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinServiceRunBelongsToSelectedProfile(t *testing.T) {
	profile := "/Users/test/LuminaVPN"
	name := "netlaunch-" + strings.Repeat("a", 32)
	root := darwinServiceRuns(os.Getuid(), darwinProfileKey(profile))
	if !MacServiceProfileRun(profile, filepath.Join(root, name)) {
		t.Fatal("service run did not bind to the selected profile")
	}
	for _, run := range []string{
		filepath.Join(root, "netlaunch-123"),
		filepath.Join(root, "nested", name),
		filepath.Join(darwinServiceRuns(os.Getuid()+1, darwinProfileKey(profile)), name),
		filepath.Join(darwinServiceRuns(os.Getuid(), darwinProfileKey(profile+"-other")), name),
		filepath.Join(profile, "runs", name),
	} {
		if MacServiceProfileRun(profile, run) {
			t.Fatalf("accepted a run outside the selected service scope: %q", run)
		}
	}
}

func TestDarwinServiceRejectsUnscopedRequests(t *testing.T) {
	key := darwinProfileKey("/Users/test/LuminaVPN")
	call := func(req darwinServiceRequest) darwinServiceReply {
		return handleDarwinServiceRequest(os.Getuid(), "/invalid/service", req)
	}
	if got := call(darwinServiceRequest{Version: darwinServiceProtocol, Action: "status"}); !got.OK || got.Build != darwinServiceBuild() {
		t.Fatal("background service status handshake failed")
	}
	for _, req := range []darwinServiceRequest{
		{Version: darwinServiceProtocol + 1, Action: "status"},
		{Version: darwinServiceProtocol, Action: "allocate", Profile: ".."},
		{Version: darwinServiceProtocol, Action: "recover-verified", Profile: key, Run: "/tmp/netlaunch-123"},
		{Version: darwinServiceProtocol, Action: "serve", Profile: key, Run: "../netlaunch-123"},
		{Version: darwinServiceProtocol, Action: "serve", Profile: key, Run: "netlaunch-123", Company: &DarwinDesktopCompanyRequest{}},
		{Version: darwinServiceProtocol, Action: "exec", Profile: key, Run: "netlaunch-" + strings.Repeat("a", 32)},
	} {
		if call(req).OK {
			t.Fatalf("accepted an invalid service request: %+v", req)
		}
	}
}

func TestDarwinServicePeerReturnsKernelAccount(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "lumina-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	addr := &net.UnixAddr{Name: filepath.Join(dir, "test.sock"), Net: "unix"}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, conn := range []*net.UnixConn{client, server} {
		if uid, err := darwinServicePeer(conn); err != nil || uid != os.Geteuid() {
			t.Fatalf("peer UID = %d, error = %v", uid, err)
		}
	}
}
