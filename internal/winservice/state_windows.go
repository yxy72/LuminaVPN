//go:build windows

package winservice

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"netlaunch/internal/platform"
	p "netlaunch/internal/serviceprotocol"
)

type installedStateFiles struct{ root string }

func (f installedStateFiles) path(relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || strings.Contains(relative, ":") || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", errors.New("invalid protected relative state")
	}
	return filepath.Join(f.root, relative), nil
}
func (f installedStateFiles) Read(relative string) ([]byte, error) {
	path, err := f.path(relative)
	if err != nil {
		return nil, err
	}
	data, err := (WindowsProtectedFiles{Root: f.root}).ReadProtected(path)
	if errors.Is(err, os.ErrNotExist) {
		// Absence is trusted only after the protected parent is verified.
		if parentErr := (WindowsProtectedFiles{Root: f.root}).validatePath(filepath.Dir(path)); parentErr != nil {
			return nil, parentErr
		}
		return nil, errProtectedStateMissing
	}
	if err != nil {
		return nil, err
	}
	if len(data) > p.MaxFrame {
		return nil, errors.New("protected state limit")
	}
	return data, nil
}
func (f installedStateFiles) Write(relative string, data []byte) error {
	if len(data) > p.MaxFrame {
		return errors.New("protected state limit")
	}
	path, err := f.path(relative)
	if err != nil {
		return err
	}
	fs := WindowsProtectedFiles{Root: f.root}
	if err = fs.validatePath(filepath.Dir(path)); err != nil {
		return err
	}
	if _, err = os.Lstat(path); err == nil {
		if err = fs.validatePath(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	id, err := newID(".pending-")
	if err != nil {
		return err
	}
	temporary := filepath.Join(filepath.Dir(path), id)
	security, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: security}
	name, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_WRITE_THROUGH, 0)
	runtime.KeepAlive(security)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), temporary)
	defer os.Remove(temporary)
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = fs.validatePath(temporary); err != nil {
		return err
	}
	// Parent is installer-protected; atomic replacement cannot be redirected
	// by an enrolled desktop user, and no directory/ACL is created or changed.
	from, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// NewInstalledHost only opens an already-reviewed machine installation. The
// installer must have provisioned the protected control, initial binding and
// bindings/operations/runs directories. Missing state remains unavailable.
func NewInstalledHost(factory func(Installation, OwnershipStore, Binding) (Backend, error)) (*Host, error) {
	return newInstalledHostRole(factory, false)
}
func NewInstalledRecoveryHost(factory func(Installation, OwnershipStore, Binding) (Backend, error)) (*Host, error) {
	return newInstalledHostRole(factory, true)
}
func newInstalledHostRole(factory func(Installation, OwnershipStore, Binding) (Backend, error), recovery bool) (*Host, error) {
	if factory == nil {
		return nil, safeError("BACKEND_UNAVAILABLE")
	}
	installation, err := LoadInstallation()
	if err != nil {
		return nil, safeError("BACKEND_UNAVAILABLE")
	}
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return nil, err
	}
	root := filepath.Join(programData, "LuminaVPN", "ServiceState")
	fs := installedStateFiles{root: root}
	for _, relative := range []string{"bindings", "operations", "runs"} {
		path := filepath.Join(root, relative)
		if err = (WindowsProtectedFiles{Root: root}).validatePath(path); err != nil {
			return nil, safeError("BACKEND_UNAVAILABLE")
		}
		info, statErr := os.Stat(path)
		if statErr != nil || !info.IsDir() {
			return nil, safeError("BACKEND_UNAVAILABLE")
		}
	}
	data, err := fs.Read("machine-control.json")
	if err != nil {
		return nil, safeError("BACKEND_UNAVAILABLE")
	}
	var control machineControl
	if err = decodeState(data, &control); err != nil {
		return nil, err
	}
	expected, err := control.binding()
	if err != nil {
		return nil, err
	}
	serviceSID := control.ServiceSID
	if recovery {
		serviceSID = control.RecoveryServiceSID
		err = verifyNamedServiceExecutor(serviceSID, RecoveryServiceName)
	} else {
		err = verifyServiceExecutor(serviceSID)
	}
	if err != nil {
		return nil, err
	}
	if recovery {
		if err = RequireMainServiceStopped(); err != nil {
			return nil, err
		}
	}
	owners, err := newFileOwnershipStore(fs, expected)
	if err != nil {
		return nil, err
	}
	binding, err := owners.Lookup(expected.ProfileID)
	if err != nil {
		return nil, err
	}
	backend, err := factory(installation, owners, binding)
	if err != nil {
		return nil, err
	}
	broker, err := NewBroker(context.Background(), backend, owners, &FileLedger{files: fs}, expected.ExecutorSID, expected.ServiceInstance)
	if err != nil {
		return nil, err
	}
	broker.validationOnly = platform.WindowsClientValidationOnly || control.ValidationOnly
	broker.serviceHost, err = platform.Process(os.Getpid())
	if err != nil || broker.serviceHost.PID != os.Getpid() || broker.serviceHost.Birth == "" {
		return nil, errors.New("actual service host identity unavailable")
	}
	broker.serviceHostSHA256 = installation.pins[ServiceImage].SHA256
	broker.lifecycleSHA256 = installation.pins[LifecycleImage].SHA256
	if receiver, ok := backend.(interface{ AttachBroker(*Broker) }); ok {
		receiver.AttachBroker(broker)
	}
	// This SID only grants pipe connection eligibility. The broker still
	// authorizes every mutation against the current exact kernel tuple.
	return &Host{Broker: broker, ServiceSID: serviceSID, LogonSID: control.AllowedOwnerSID, Installation: installation}, nil
}

func verifyServiceExecutor(expectedSID string) error {
	return verifyNamedServiceExecutor(expectedSID, ServiceName)
}
func verifyNamedServiceExecutor(expectedSID, name string) error {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user.User.Sid.String() != "S-1-5-18" {
		return errors.New("protected LocalSystem service executor required")
	}
	actual, _, _, err := windows.LookupSID("", "NT SERVICE\\"+name)
	if err != nil || actual.String() != expectedSID {
		return errors.New("installed service SID differs")
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return err
	}
	for _, group := range groups.AllGroups() {
		if group.Sid.Equals(actual) && group.Attributes&windows.SE_GROUP_ENABLED != 0 && group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			return nil
		}
	}
	return errors.New("service executor token is missing its service SID")
}

// LoadPreparedBinding is a read-only check for the fixed service helper. It
// reopens the installed enrollment and persisted prepared identity instead of
// trusting a serve request's claim that BindPreparedRun succeeded.
func LoadPreparedBinding(profileID string) (Binding, error) {
	binding, err := loadEnrolledBinding(profileID)
	if err != nil {
		return Binding{}, err
	}
	if binding.RunRef == "" || binding.PreparedRunID == "" || binding.SpecDigest == "" {
		return Binding{}, errors.New("prepared service identity is not durably bound")
	}
	return binding, nil
}
func loadEnrolledBinding(profileID string) (Binding, error) {
	return loadEnrolledBindingRole(profileID, false)
}
func loadEnrolledBindingRole(profileID string, recovery bool) (Binding, error) {
	if !ValidProfileID(profileID) {
		return Binding{}, errors.New("invalid enrolled profile")
	}
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return Binding{}, err
	}
	fs := installedStateFiles{root: filepath.Join(programData, "LuminaVPN", "ServiceState")}
	data, err := fs.Read("machine-control.json")
	if err != nil {
		return Binding{}, err
	}
	var control machineControl
	if err = decodeState(data, &control); err != nil {
		return Binding{}, err
	}
	expected, err := control.binding()
	if err != nil {
		return Binding{}, err
	}
	if recovery {
		err = verifyNamedServiceExecutor(control.RecoveryServiceSID, RecoveryServiceName)
	} else {
		err = verifyServiceExecutor(control.ServiceSID)
	}
	if err != nil {
		return Binding{}, err
	}
	store, err := newFileOwnershipStore(fs, expected)
	if err != nil {
		return Binding{}, err
	}
	binding, err := store.Lookup(profileID)
	if err != nil {
		return Binding{}, err
	}
	return binding, nil
}

func LoadRecoveryBinding(profileID string) (Binding, error) {
	// A recovery token cannot silently become a start/control token.
	if _, err := LoadInstallation(); err != nil {
		return Binding{}, err
	}
	binding, err := loadEnrolledBindingRole(profileID, true)
	if err != nil {
		return Binding{}, err
	}
	if binding.RunRef == "" || binding.PreparedRunID == "" || binding.SpecDigest == "" {
		return Binding{}, errors.New("exact recovery binding unavailable")
	}
	return binding, nil
}
