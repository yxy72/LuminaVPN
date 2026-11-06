//go:build windows

package winservice

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	p "netlaunch/internal/serviceprotocol"
	"netlaunch/internal/winprofile"
)

func servicePresence() localPresence {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return presenceUnknown
	}
	defer windows.CloseServiceHandle(manager)
	name, _ := windows.UTF16PtrFromString(ServiceName)
	service, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return presenceAbsent
	}
	if err != nil {
		return presenceUnknown
	}
	windows.CloseServiceHandle(service)
	return presencePresent
}

// pathPresence follows no reparse point between the native known-folder
// anchor and the exact fixed target. Absence of any component is sufficient;
// access denied, junctions and all other errors remain unknown.
func pathPresence(anchor, target string) localPresence {
	parts, anchorIndex, ok := localPathChain(anchor, target)
	if !ok {
		return presenceUnknown
	}
	for index, path := range parts {
		_, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			if index <= anchorIndex {
				return presenceUnknown
			}
			return presenceAbsent
		}
		if err != nil {
			return presenceUnknown
		}
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return presenceUnknown
		}
		attributes, err := windows.GetFileAttributes(name)
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return presenceUnknown
		}
	}
	return presencePresent
}

func localPathChain(anchor, target string) ([]string, int, bool) {
	volume := filepath.VolumeName(anchor)
	if len(volume) != 2 || volume[1] != ':' || !((volume[0] >= 'A' && volume[0] <= 'Z') || (volume[0] >= 'a' && volume[0] <= 'z')) || !filepath.IsAbs(anchor) || !filepath.IsAbs(target) || filepath.Clean(anchor) != anchor || filepath.Clean(target) != target || !strings.EqualFold(volume, filepath.VolumeName(target)) || strings.Contains(anchor[2:], ":") || strings.Contains(target[2:], ":") {
		return nil, 0, false
	}
	relative, err := filepath.Rel(anchor, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return nil, 0, false
	}
	root := volume + string(os.PathSeparator)
	parts := []string{root}
	current := root
	anchorIndex := -1
	if strings.EqualFold(anchor, root) {
		anchorIndex = 0
	}
	for _, part := range strings.Split(strings.TrimPrefix(target[len(volume):], string(os.PathSeparator)), string(os.PathSeparator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		parts = append(parts, current)
		if strings.EqualFold(current, anchor) {
			anchorIndex = len(parts) - 1
		}
	}
	return parts, anchorIndex, anchorIndex >= 0
}

func localAbsentSnapshot(profile string) (p.Snapshot, bool) {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil || checkProtectedACL(programFiles) != nil {
		return p.Snapshot{}, false
	}
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return p.Snapshot{}, false
	}
	evidence := localAbsenceEvidence{service: servicePresence(), installation: pathPresence(programFiles, filepath.Join(programFiles, "LuminaVPN"))}
	evidence.owned = append(evidence.owned, pathPresence(programData, filepath.Join(programData, "LuminaVPN", "ServiceState")), pathPresence(programData, filepath.Join(programData, "NetLaunch")))
	currentProfile, err := winprofile.PathForToken(windows.GetCurrentProcessToken())
	if err != nil {
		return p.Snapshot{}, false
	}
	if localProfileID(currentProfile) == profile {
		evidence.defaultProfile = true
	}
	evidence.owned = append(evidence.owned, pathPresence(programData, filepath.Join(currentProfile, "current.json")), pathPresence(programData, filepath.Join(currentProfile, "runs")))
	for _, location := range []struct {
		folder *windows.KNOWNFOLDERID
		leaf   string
	}{{windows.FOLDERID_Profile, ".netlaunch"}, {windows.FOLDERID_RoamingAppData, "NetLaunch"}, {windows.FOLDERID_LocalAppData, "NetLaunch"}} {
		base, err := windows.KnownFolderPath(location.folder, windows.KF_FLAG_DEFAULT)
		if err != nil {
			return p.Snapshot{}, false
		}
		root := filepath.Join(base, location.leaf)
		if localProfileID(root) == profile {
			evidence.defaultProfile = true
		}
		evidence.owned = append(evidence.owned, pathPresence(base, filepath.Join(root, "current.json")), pathPresence(base, filepath.Join(root, "runs")))
	}
	return absentSnapshot(profile, evidence)
}
