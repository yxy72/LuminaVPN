//go:build windows

package winservice

import (
	"encoding/binary"
	"errors"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var regGetKeySecurity = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegGetKeySecurity")

type windowsLegacyRegistry struct{}
type windowsLegacyRegistryKey struct {
	key  registry.Key
	held []registry.Key
}

func (key *windowsLegacyRegistryKey) Close() error {
	var result error
	for i := len(key.held) - 1; i >= 0; i-- {
		result = errors.Join(result, key.held[i].Close())
	}
	key.held = nil
	return result
}

func (key *windowsLegacyRegistryKey) StringValue(name string) (string, error) {
	// A single bounded read avoids allocating based on mutable registry data.
	buffer := make([]byte, 4096)
	n, kind, err := key.key.GetValue(name, buffer)
	if err != nil {
		return "", err
	}
	if kind != registry.SZ || n < 2 || n > len(buffer) || n%2 != 0 {
		return "", errors.New("legacy value must be a bounded literal REG_SZ")
	}
	units := make([]uint16, n/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(buffer[i*2:])
		if units[i] == 0 && i != len(units)-1 {
			return "", errors.New("legacy value contains an embedded terminator")
		}
	}
	if units[len(units)-1] != 0 {
		return "", errors.New("legacy value is not terminated")
	}
	return string(utf16.Decode(units[:len(units)-1])), nil
}

func openRegistryLinkItself(parent registry.Key, path string, view uint32) (registry.Key, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var handle windows.Handle
	// REG_OPTION_OPEN_LINK: inspect the final component, never its link target.
	err = windows.RegOpenKeyEx(windows.Handle(parent), name, 8, windows.READ_CONTROL|registry.QUERY_VALUE|view, &handle)
	return registry.Key(handle), err
}

func (windowsLegacyRegistry) HasCurrentUserKey(view uint32, path string) (bool, error) {
	key, err := openRegistryLinkItself(registry.CURRENT_USER, path, view)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, key.Close()
}

func (windowsLegacyRegistry) OpenMachine(view uint32, path string) (result legacyRegistryKey, err error) {
	if (view != registry.WOW64_64KEY && view != registry.WOW64_32KEY) || !strings.HasPrefix(path, `Software\`) || len(path) > 512 {
		return nil, errors.New("unexpected fixed registry path or view")
	}
	key := &windowsLegacyRegistryKey{}
	defer func() {
		if err != nil {
			err = errors.Join(err, key.Close())
		}
	}()
	installer, _, _, lookupErr := windows.LookupSID("", `NT SERVICE\TrustedInstaller`)
	if lookupErr != nil {
		return nil, lookupErr
	}
	current := registry.LOCAL_MACHINE
	if err = checkRegistryKey(current, installer.String()); err != nil {
		return nil, err
	}
	for _, component := range strings.Split(path, `\`) {
		if component == "" || component == "." || component == ".." {
			return nil, errors.New("invalid registry component")
		}
		var next registry.Key
		next, err = openRegistryLinkItself(current, component, view)
		if errors.Is(err, registry.ErrNotExist) {
			// The last existing parent has already been checked for CREATE_SUB_KEY
			// and security/replace rights, so an untrusted user cannot fill this gap.
			return nil, errLegacyRegistryMissing
		}
		if err != nil {
			return nil, err
		}
		key.held = append(key.held, next)
		if err = checkRegistryKey(next, installer.String()); err != nil {
			return nil, err
		}
		current = next
	}
	key.key = current
	return key, nil
}

func checkRegistryKey(key registry.Key, trustedInstaller string) error {
	// RegGetKeySecurity supports predefined HKLM as well as opened component
	// handles. Every descriptor is read from the exact handle used for traversal.
	information := uintptr(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	var length uint32
	status, _, _ := regGetKeySecurity.Call(uintptr(key), information, 0, uintptr(unsafe.Pointer(&length)))
	if status != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) || length < 20 || length > 65536 {
		return errors.New("registry security size is unknown")
	}
	buffer := make([]byte, length)
	status, _, _ = regGetKeySecurity.Call(uintptr(key), information, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&length)))
	if status != 0 {
		return syscall.Errno(status)
	}
	defer runtime.KeepAlive(buffer)
	sd := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&buffer[0]))
	if !sd.IsValid() {
		return errors.New("invalid registry security descriptor")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		return errors.New("registry owner is unknown")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount > 512 {
		return errors.New("registry DACL is absent or unbounded")
	}
	entries := make([]protectedACE, 0, acl.AceCount)
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(acl, i, &ace); err != nil || ace == nil {
			return errors.New("registry ACE is unknown")
		}
		entry := protectedACE{Kind: ace.Header.AceType, Flags: ace.Header.AceFlags}
		if entry.Kind == windows.ACCESS_ALLOWED_ACE_TYPE && entry.Flags&8 == 0 {
			if ace.Header.AceSize < 16 {
				return errors.New("registry allow ACE is truncated")
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !sid.IsValid() || sid.Len() > int(ace.Header.AceSize)-8 {
				return errors.New("registry allow SID is truncated")
			}
			entry.Mask, entry.SID = uint32(ace.Mask), sid.String()
		}
		entries = append(entries, entry)
	}
	if err = validateRegistryDescriptor(owner.String(), entries, trustedInstaller); err != nil {
		return err
	}
	_, kind, err := key.GetValue("SymbolicLinkValue", nil)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if kind == registry.LINK {
		return errors.New("registry symbolic link is not an installer authority")
	}
	return nil
}
