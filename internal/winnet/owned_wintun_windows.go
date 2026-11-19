//go:build windows

package winnet

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	wintunInterfaceType = 53
	netLUIDIndexMask    = 0xffffff
	cmLocateNormal      = 0
	cmLocatePhantom     = 1
)

var (
	netSetupClass = windows.GUID{
		Data1: 0x4d36e972, Data2: 0xe325, Data3: 0x11ce,
		Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18},
	}
	locateWintunDevnode = windows.NewLazySystemDLL("cfgmgr32.dll").NewProc("CM_Locate_DevNodeW")
	openWintunDevinfo   = windows.NewLazySystemDLL("setupapi.dll").NewProc("SetupDiOpenDeviceInfoW")
)

// RemoveOwnedWintunAdapter is a recovery operation for a previously verified
// run. Its caller must hold recovery ownership, have stopped the owning jobs
// and restored journaled network changes. Only the exact Down, nonpresent
// Windows software device can be removed. A no-op or a dispatched removal is
// never evidence of absence; the caller must perform strict post-readback.
func RemoveOwnedWintunAdapter(expected Adapter) (removed bool, err error) {
	instance, err := ownedWintunInstance(expected)
	if err != nil {
		return false, err
	}
	if err := locateWintunDevnode.Find(); err != nil {
		return false, err
	}
	if err := openWintunDevinfo.Find(); err != nil {
		return false, err
	}
	id, err := windows.UTF16PtrFromString(instance)
	if err != nil {
		return false, err
	}
	ready, err := exactOwnedWintunDown(expected, wintunInterfaceRow, presenceGUIDLUID)
	if err != nil || !ready {
		return false, err
	}
	_, present, err := locateExactWintunNode(id, cmLocateNormal)
	if err != nil || present {
		return false, err
	}
	phantom, exists, err := locateExactWintunNode(id, cmLocatePhantom)
	if err != nil || !exists {
		return false, err
	}

	set, err := windows.SetupDiCreateDeviceInfoListEx(&netSetupClass, 0, "")
	if err != nil {
		return false, err
	}
	defer set.Close()
	// No output buffer is needed here. EnumDeviceInfo picks the sole entry in
	// this private list and uses the x/sys-managed SP_DEVINFO_DATA ABI.
	ok, _, callErr := openWintunDevinfo.Call(uintptr(set), uintptr(unsafe.Pointer(id)), 0, 0, 0)
	if ok == 0 {
		_, exists, readErr := locateExactWintunNode(id, cmLocatePhantom)
		if readErr == nil && !exists {
			return false, nil
		}
		return false, fmt.Errorf("open exact Wintun device instance: %w", callErr)
	}
	data, err := windows.SetupDiEnumDeviceInfo(set, 0)
	if err != nil {
		return false, err
	}
	actual, err := set.DeviceInstanceID(data)
	if err != nil {
		return false, err
	}
	if data.ClassGUID != netSetupClass || data.DevInst != phantom || !strings.EqualFold(actual, instance) {
		return false, errors.New("exact Wintun device instance changed")
	}
	if err := verifyOwnedWintunDriver(set, data, expected); err != nil {
		return false, err
	}
	params, err := set.DeviceInstallParams(data)
	if err != nil {
		return false, err
	}
	params.Flags |= windows.DI_QUIETINSTALL
	if err = set.SetDeviceInstallParams(data, params); err != nil {
		return false, err
	}
	remove := windows.RemoveDeviceParams{
		ClassInstallHeader: *windows.MakeClassInstallHeader(windows.DIF_REMOVE),
		Scope:              windows.DI_REMOVEDEVICE_GLOBAL,
	}
	if err = set.SetClassInstallParams(data, &remove.ClassInstallHeader, uint32(unsafe.Sizeof(remove))); err != nil {
		return false, err
	}

	ready, err = exactOwnedWintunDown(expected, wintunInterfaceRow, presenceGUIDLUID)
	if err != nil || !ready {
		return false, err
	}
	current, exists, err := locateExactWintunNode(id, cmLocatePhantom)
	if err != nil || !exists {
		return false, err
	}
	if current != phantom {
		return false, errors.New("exact Wintun device changed before removal")
	}
	_, present, err = locateExactWintunNode(id, cmLocateNormal)
	if err != nil || present {
		return false, err
	}
	if err := windows.SetupDiCallClassInstaller(windows.DIF_REMOVE, set, data); err != nil {
		return false, err
	}
	params, err = set.DeviceInstallParams(data)
	if err != nil {
		return true, err
	}
	if params.Flags&(windows.DI_NEEDRESTART|windows.DI_NEEDREBOOT) != 0 {
		return true, errors.New("exact Wintun device removal requires a restart")
	}
	return true, nil
}

func ownedWintunInstance(expected Adapter) (string, error) {
	if err := validPresenceIdentity(expected); err != nil {
		return "", err
	}
	if expected.LUID>>48 != wintunInterfaceType || expected.LUID&netLUIDIndexMask != 0 ||
		(expected.LUID>>24)&netLUIDIndexMask == 0 {
		return "", errors.New("invalid owned Wintun LUID")
	}
	guid, err := windows.GUIDFromString(expected.GUID)
	if err != nil {
		return "", err
	}
	return `SWD\WINTUN\` + guid.String(), nil
}

func wintunInterfaceRow(luid uint64, index uint32) (windows.MibIfRow2, error) {
	row := windows.MibIfRow2{InterfaceLuid: luid, InterfaceIndex: index}
	err := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row)
	return row, err
}

func exactOwnedWintunDown(expected Adapter, lookup func(uint64, uint32) (windows.MibIfRow2, error), guidToLUID func(string) (uint64, error)) (bool, error) {
	down := true
	for _, key := range []struct {
		luid  uint64
		index uint32
	}{{luid: expected.LUID}, {index: expected.Index}} {
		row, err := lookup(key.luid, key.index)
		if presenceNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		actual := Adapter{
			GUID: row.InterfaceGuid.String(), Index: row.InterfaceIndex, LUID: row.InterfaceLuid,
			Name: windows.UTF16ToString(row.Alias[:]), Type: row.Type, Hardware: row.InterfaceAndOperStatusFlags&1 != 0,
		}
		if !samePresenceIdentity(expected, actual) {
			return false, errors.New("owned Wintun interface identity changed")
		}
		down = down && row.OperStatus == windows.IfOperStatusDown
	}
	if !down {
		return false, nil
	}
	luid, err := guidToLUID(expected.GUID)
	if presenceNotFound(err) || errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if luid != expected.LUID {
		return false, errors.New("owned Wintun GUID resolves to a different interface")
	}
	return true, nil
}

func locateExactWintunNode(id *uint16, flag uintptr) (windows.DEVINST, bool, error) {
	var node windows.DEVINST
	code, _, _ := locateWintunDevnode.Call(uintptr(unsafe.Pointer(&node)), uintptr(unsafe.Pointer(id)), flag)
	switch result := windows.CONFIGRET(code); result {
	case windows.CR_SUCCESS:
		return node, true, nil
	case windows.CR_NO_SUCH_DEVNODE:
		return 0, false, nil
	default:
		return 0, false, result
	}
}

func verifyOwnedWintunDriver(set windows.DevInfo, data *windows.DevInfoData, expected Adapter) error {
	hardware, err := set.DeviceRegistryProperty(data, windows.SPDRP_HARDWAREID)
	if err != nil {
		return err
	}
	service, err := set.DeviceRegistryProperty(data, windows.SPDRP_SERVICE)
	if err != nil {
		return err
	}
	hardwareIDs, ok := hardware.([]string)
	driverService, serviceOK := service.(string)
	if !ok || len(hardwareIDs) != 1 || !strings.EqualFold(hardwareIDs[0], "Wintun") ||
		!serviceOK || !strings.EqualFold(driverService, "wintun") {
		return errors.New("owned software device is not a Wintun device")
	}
	handle, err := windows.SetupDiOpenDevRegKey(set, data, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	key := registry.Key(handle)
	defer key.Close()
	component, _, err := key.GetStringValue("ComponentId")
	if err != nil {
		return err
	}
	guid, _, err := key.GetStringValue("NetCfgInstanceId")
	if err != nil {
		return err
	}
	index, _, err := key.GetIntegerValue("NetLuidIndex")
	if err != nil {
		return err
	}
	ifType, _, err := key.GetIntegerValue("*IfType")
	if err != nil {
		return err
	}
	if !strings.EqualFold(component, "Wintun") || !strings.EqualFold(guid, expected.GUID) ||
		index != (expected.LUID>>24)&netLUIDIndexMask || ifType != wintunInterfaceType {
		return errors.New("owned Wintun driver registration differs from the frozen interface")
	}
	return nil
}
