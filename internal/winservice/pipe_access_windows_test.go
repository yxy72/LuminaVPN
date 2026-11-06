//go:build windows

package winservice

import (
	"context"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Exercise the real Win32 client API against fresh task-owned pipes. No
// installed endpoint, service, enrollment, or machine security is changed.
func TestNativePipeClientExplicitAccess(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if user.User.Sid.String() == "S-1-5-18" {
		t.Skip("SYSTEM has intentional full pipe access and cannot exercise the client-only DACL")
	}
	sddl, err := PipeSDDL("S-1-5-80-1-2-3", user.User.Sid.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		sddl   string
		rights uint32
		deny   bool
	}{
		{"missing_read_attributes", strings.Replace(sddl, "0x00100083", "0x00100003", 1), 0x00100003, true},
		{"explicit_client_access", sddl, PipeClientRights, false},
		{"no_write_attributes", sddl, PipeClientRights | windows.FILE_WRITE_ATTRIBUTES, true},
		{"no_generic_write", sddl, windows.GENERIC_WRITE, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			id, err := newID("access-")
			if err != nil {
				t.Fatal(err)
			}
			name, _ := windows.UTF16PtrFromString(`\\.\pipe\LuminaVPN.Test.` + id)
			sd, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal(err)
			}
			sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
			server, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|PipeFirstInstance, PipeRejectRemote, 2, 4096, 4096, 0, &sa)
			runtime.KeepAlive(sd)
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(server)
			// Test the actual server-instance API. Client-side FILE_APPEND_DATA
			// requests do not establish permission to create a server instance.
			second, secondErr := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED, PipeRejectRemote, 2, 4096, 4096, 0, &sa)
			if secondErr == nil {
				windows.CloseHandle(second)
				t.Fatal("client-only DACL allowed another server instance")
			}
			if !errors.Is(secondErr, windows.ERROR_ACCESS_DENIED) {
				t.Fatalf("unexpected server-instance rejection: %v", secondErr)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			finished := make(chan error, 1)
			go func() {
				if err := connectInstance(ctx, server); err != nil {
					finished <- err
					return
				}
				connection := &pipeIO{handle: server, ctx: ctx}
				var request [1]byte
				if _, err := io.ReadFull(connection, request[:]); err != nil {
					finished <- err
					return
				}
				if request[0] != 0x4c {
					finished <- errors.New("unexpected test frame")
					return
				}
				_, err := connection.Write([]byte{0x50})
				finished <- err
			}()
			defer func() { cancel(); <-finished }()
			client, err := windows.CreateFile(name, test.rights, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IMPERSONATION, 0)
			if test.deny {
				if err == nil {
					windows.CloseHandle(client)
					t.Fatal("Win32 pipe open accepted rights outside the client DACL")
				}
				if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
					t.Fatalf("unexpected denied-open error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("explicit client rights failed Win32 pipe open: %v", err)
			}
			connection := &pipeIO{handle: client, ctx: ctx, owned: true}
			defer connection.Close()
			if _, err := connection.Write([]byte{0x4c}); err != nil {
				t.Fatal(err)
			}
			var response [1]byte
			if _, err := io.ReadFull(connection, response[:]); err != nil || response[0] != 0x50 {
				t.Fatalf("explicit client rights failed pipe exchange: %v", err)
			}
		})
	}
}
