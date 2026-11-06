//go:build windows

package winservice

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var ntCreateRegistryKey = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtCreateKey")

// Invoked only by the fresh nonce-bound administrator resume entry while its
// installer lock is held. This owns two product leaves, never a shared parent.
// Failed or interrupted claims may leave an empty protected leaf for retry.
func claimFixedMachineRegistry(ctx context.Context) error {
	for _, path := range []string{`Software\` + luminaUninstallID(), legacyUninstallPrefix + luminaUninstallID()} {
		if err := ctx.Err(); err != nil {
			return err
		}
		key, err := openMachineRegistryPath(registry.WOW64_64KEY, path, true)
		if err != nil {
			return err
		}
		if err = key.Close(); err != nil {
			return err
		}
	}
	return nil
}

func claimRegistryLeaf(parent registry.Key, component string, view uint32, trustedInstaller string) (registry.Key, error) {
	if component == "" || component == "." || component == ".." || len(component) > 128 || strings.ContainsAny(component, "\\/\x00") || (view != registry.WOW64_64KEY && view != registry.WOW64_32KEY) {
		return 0, errors.New("invalid fixed registry leaf")
	}
	name, err := windows.NewNTUnicodeString(component)
	if err != nil {
		return 0, err
	}
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)")
	if err != nil {
		return 0, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{RootDirectory: windows.Handle(parent), ObjectName: name,
		Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_OPENLINK, SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	var handle windows.Handle
	var disposition uint32
	// A relative single component and OBJ_OPENLINK prevent an attacker-created
	// final symbolic link being followed between observation and creation. An
	// existing key keeps its descriptor: it must pass inspection, never repair.
	status, _, _ := ntCreateRegistryKey.Call(uintptr(unsafe.Pointer(&handle)),
		uintptr(windows.READ_CONTROL|registry.QUERY_VALUE|view), uintptr(unsafe.Pointer(&attributes)),
		0, 0, 0, uintptr(unsafe.Pointer(&disposition)))
	runtime.KeepAlive(name)
	runtime.KeepAlive(sd)
	if status != 0 {
		return 0, windows.NTStatus(status).Errno()
	}
	key := registry.Key(handle)
	if disposition != 1 && disposition != 2 {
		return 0, errors.Join(errors.New("unknown registry claim disposition"), key.Close())
	}
	if err = checkRegistryKey(key, trustedInstaller); err != nil {
		return 0, errors.Join(err, key.Close())
	}
	return key, nil
}

// Conflict probes confer no execution or deletion authority. In particular an
// absent alias/32-bit key need not have a parent that forbids creating siblings.
func (windowsLegacyRegistry) ProbeMachine(view uint32, path string) (bool, error) {
	if (view != registry.WOW64_64KEY && view != registry.WOW64_32KEY) || !strings.HasPrefix(path, `Software\`) || len(path) > 512 {
		return false, errors.New("unexpected fixed registry probe")
	}
	current := registry.LOCAL_MACHINE
	var held []registry.Key
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			_ = held[i].Close()
		}
	}()
	for _, component := range strings.Split(path, `\`) {
		if component == "" || component == "." || component == ".." {
			return false, errors.New("invalid registry probe component")
		}
		next, err := openRegistryLinkItself(current, component, view)
		if errors.Is(err, registry.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		held = append(held, next)
		if err = rejectRegistryLink(next); err != nil {
			return false, err
		}
		current = next
	}
	return true, nil
}
